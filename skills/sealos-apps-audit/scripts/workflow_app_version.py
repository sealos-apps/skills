"""Conservative, read-only evidence parsing for chart appVersion stamping."""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class WorkflowAppVersionWrite:
    path: Path
    line: int
    targets: frozenset[str]
    tag_source: bool
    sha_source: bool
    before_packaging: bool
    job_id: str = ""
    guard_profile: str = "unconditional"


@dataclass(frozen=True)
class WorkflowStep:
    start_line: int
    end_line: int
    text: str
    command: str
    working_directory: str | None
    condition: str


@dataclass(frozen=True)
class WorkflowJob:
    path: Path
    job_id: str
    start_line: int
    end_line: int
    text: str
    needs: frozenset[str]
    condition: str
    steps: tuple[WorkflowStep, ...]


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _top_key(line: str, key: str) -> bool:
    return bool(re.match(rf"^(?:['\"]?{re.escape(key)}['\"]?)\s*:", line.lstrip("\ufeff")))


def workflow_on_block(text: str) -> str:
    """Extract only the top-level Actions ``on`` block."""
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if not _top_key(line, "on") or _indent(line) != 0:
            continue
        block = [line]
        for next_line in lines[index + 1 :]:
            if next_line.strip() and _indent(next_line) == 0:
                break
            block.append(next_line)
        return "\n".join(block)
    return ""


def _scalar_events(value: str) -> set[str]:
    value = value.strip()
    if not value:
        return set()
    if value.startswith("[") and value.endswith("]"):
        return {part.strip().strip("'\"") for part in value[1:-1].split(",") if part.strip()}
    return {value.strip("'\"")} if value.strip("'\"") else set()


KNOWN_WORKFLOW_EVENTS = {
    "push",
    "release",
    "pull_request",
    "pull_request_target",
    "schedule",
    "workflow_dispatch",
    "workflow_call",
    "repository_dispatch",
    "workflow_run",
}


def workflow_trigger_profile(text: str) -> str:
    """Classify trigger paths as tag-only, sha/non-tag, or mixed."""
    block = workflow_on_block(text)
    if not block:
        return "mixed"
    lines = block.splitlines()
    rhs = lines[0].split(":", 1)[1].strip() if ":" in lines[0] else ""
    if rhs.startswith("{"):
        # Inline event maps need a real YAML parser; never guess sha-only here.
        return "mixed"
    events = _scalar_events(rhs)
    push_lines: list[str] = []
    malformed = bool(rhs and not events)
    if not rhs:
        for index, line in enumerate(lines[1:], start=1):
            match = re.match(r"^  ([A-Za-z][A-Za-z0-9_-]*)\s*:\s*(.*)$", line)
            if not match:
                if line.strip() and _indent(line) <= 2:
                    malformed = True
                continue
            event, remainder = match.groups()
            events.add(event)
            if event.lower() == "push":
                push_lines = [line]
                for nested in lines[index + 1 :]:
                    if nested.strip() and _indent(nested) <= 2:
                        break
                    push_lines.append(nested)
    event_names = {event.lower() for event in events}
    if malformed or not events or not event_names <= KNOWN_WORKFLOW_EVENTS:
        return "mixed"
    tag = "release" in {event.lower() for event in events}
    sha = False
    if "push" in {event.lower() for event in events}:
        push_text = "\n".join(push_lines)
        has_tags = bool(re.search(r"^\s{4}tags\s*:", push_text, re.IGNORECASE | re.MULTILINE))
        has_tags_ignore = bool(re.search(r"^\s{4}tags-ignore\s*:", push_text, re.IGNORECASE | re.MULTILINE))
        has_branches = bool(re.search(r"^\s{4}branches(?:-ignore)?\s*:", push_text, re.IGNORECASE | re.MULTILINE))
        if (has_tags or has_tags_ignore) and not has_branches and not (has_tags and has_tags_ignore):
            tag = True
        elif has_branches and not has_tags and not has_tags_ignore:
            sha = True
        else:
            tag = sha = True
    non_push_events = event_names - {"push", "release"}
    if non_push_events:
        # These events can be invoked on either a tag or a branch. Pull requests
        # and schedules provide a commit identity but are not release-tag paths.
        if non_push_events & {"workflow_dispatch", "workflow_call", "repository_dispatch", "workflow_run"}:
            tag = sha = True
        elif non_push_events & {"pull_request", "pull_request_target", "schedule"}:
            sha = True
    if re.search(r"(?:github\.ref_type|GITHUB_REF_TYPE)\s*(?:==|!=|=)", text, re.IGNORECASE):
        tag = sha = True
    return "mixed" if tag == sha else ("tag" if tag else "sha")


def _parse_needs(text: str) -> frozenset[str]:
    needs: set[str] = set()
    for match in re.finditer(r"(?m)^ {4}needs\s*:\s*(.+)$", text):
        value = match.group(1).split("#", 1)[0].strip()
        if value.startswith("[") and value.endswith("]"):
            needs.update(part.strip().strip("'\"") for part in value[1:-1].split(",") if part.strip())
        elif re.match(r"^[A-Za-z0-9_.-]+$", value):
            needs.add(value)
    return frozenset(needs)


def _field_value(text: str, field: str, indent: int) -> str:
    values = []
    pattern = re.compile(rf"^{ ' ' * indent}{re.escape(field)}\s*:\s*(.*)$", re.IGNORECASE)
    for line in text.splitlines():
        match = pattern.match(line)
        if match:
            values.append(match.group(1).strip())
    return "\n".join(values)


def _run_value(lines: list[str], start: int, end: int) -> str:
    commands: list[str] = []
    for index in range(start, end):
        match = re.match(r"^(\s*)(?:-\s+)?run\s*:\s*(.*)$", lines[index])
        if not match:
            continue
        key_indent, value = len(match.group(1)), match.group(2).strip()
        if value in {"|", ">", "|-", ">-", "|+", ">+"}:
            index += 1
            while index < end and (not lines[index].strip() or _indent(lines[index]) > key_indent):
                if lines[index].strip():
                    commands.append(lines[index].strip())
                index += 1
        elif value:
            commands.append(value)
    return "\n".join(commands)


def _parse_steps(lines: list[str], start: int, end: int) -> tuple[WorkflowStep, ...]:
    steps_indent = None
    for index in range(start, end):
        match = re.match(r"^(\s*)steps\s*:", lines[index])
        if match:
            steps_indent = len(match.group(1)) + 2
            break
    if steps_indent is None:
        return ()
    starts = [
        index
        for index in range(start, end)
        if _indent(lines[index]) == steps_indent and re.match(r"^\s*-\s*", lines[index])
    ]
    steps: list[WorkflowStep] = []
    for position, step_start in enumerate(starts):
        step_end = starts[position + 1] if position + 1 < len(starts) else end
        step_lines = lines[step_start:step_end]
        text = "\n".join(step_lines)
        working_directory = None
        for line in step_lines:
            match = re.match(r"^\s*(?:-\s+)?working-directory\s*:\s*(.+)$", line, re.IGNORECASE)
            if match:
                working_directory = match.group(1).split("#", 1)[0].strip().strip("'\"")
                break
        conditions = []
        for line in step_lines:
            match = re.match(r"^\s*(?:-\s+)?if\s*:\s*(.+)$", line, re.IGNORECASE)
            if match:
                conditions.append(match.group(1).strip())
        steps.append(WorkflowStep(step_start + 1, step_end, text, _run_value(lines, step_start, step_end), working_directory, "\n".join(conditions)))
    return tuple(steps)


def workflow_jobs(path: Path, text: str) -> tuple[WorkflowJob, ...]:
    """Parse the small, stable subset of Actions YAML needed for job ordering."""
    lines = text.splitlines()
    jobs_index = next((index for index, line in enumerate(lines) if _top_key(line, "jobs") and _indent(line) == 0), None)
    if jobs_index is None:
        return ()
    headers = []
    for index in range(jobs_index + 1, len(lines)):
        if lines[index].strip() and _indent(lines[index]) == 0:
            break
        match = re.match(r"^  ([A-Za-z0-9_.-]+)\s*:\s*(?:.*)$", lines[index])
        if match:
            headers.append((index, match.group(1)))
    jobs: list[WorkflowJob] = []
    for position, (start, job_id) in enumerate(headers):
        end = headers[position + 1][0] if position + 1 < len(headers) else len(lines)
        job_text = "\n".join(lines[start:end])
        condition = _field_value(job_text, "if", 4)
        jobs.append(WorkflowJob(path, job_id, start + 1, end, job_text, _parse_needs(job_text), condition, _parse_steps(lines, start, end)))
    return tuple(jobs)


def _normalize_path(value: str, root: Path) -> str | None:
    value = value.strip().strip("'\"").rstrip(",;)")
    if "\\" in value:
        # Workflows in this audit run on POSIX runners. Treating a Windows
        # separator as a POSIX separator can attribute an external operand to
        # a repository chart that the shell never touched.
        return None
    root_text = root.as_posix().rstrip("/")
    workspace = re.compile(r"^\$\{\{\s*github\.workspace\s*\}\}(.*)$", re.IGNORECASE)
    workspace_match = workspace.match(value)
    if workspace_match:
        suffix = workspace_match.group(1)
        if suffix == "":
            value = "."
        elif suffix.startswith("/"):
            value = suffix[1:]
        else:
            return None
    value = re.sub(r"\$GITHUB_WORKSPACE(?:/|$)", "", value, flags=re.IGNORECASE)
    if value == root_text:
        value = "."
    elif value.startswith(root_text + "/"):
        value = value[len(root_text) + 1 :]
    if value.startswith("/") or ".." in value.split("/"):
        return None
    if any(char in value for char in "*$?[]{}"):
        return None
    normalized = posixpath.normpath(value or ".")
    if normalized == ".." or normalized.startswith("../"):
        return None
    return normalized


def _working_directories(context: str, root: Path) -> list[str]:
    values = re.findall(r"(?m)^\s*working-directory\s*:\s*([^\s#]+)", context, re.IGNORECASE)
    values += re.findall(r'''\bcd\s+(['"]?[^\s;&|\'"]+)''', context, re.IGNORECASE)
    result = []
    for value in values:
        normalized = _normalize_path(value, root)
        if normalized is not None:
            result.append(normalized)
    return result


def _path_refs(context: str) -> list[str]:
    refs: list[str] = []
    words = _shell_words(context)
    for index, token in enumerate(words):
        token = token.lstrip(">")
        if token.startswith("./"):
            candidate = token
        else:
            candidate = token
        candidate = candidate.strip("'\"")
        if candidate == "Chart.yaml" and index and words[index - 1].strip("'\"") in {"-name", "--name"}:
            continue
        if candidate == "Chart.yaml" or candidate.endswith("/Chart.yaml"):
            refs.append(candidate)
    return refs


def _shell_words(text: str) -> list[str]:
    """Split simple shell words without interpreting their contents."""
    words: list[str] = []
    current: list[str] = []
    quote: str | None = None
    escaped = False

    def flush() -> None:
        if current:
            words.append("".join(current))
            current.clear()

    for character in text:
        if escaped:
            current.append(character)
            escaped = False
            continue
        if quote:
            current.append(character)
            if character == quote:
                quote = None
            elif character == "\\" and quote == '"':
                escaped = True
            continue
        if character in {"'", '"'}:
            current.append(character)
            quote = character
        elif character == "\\":
            current.append(character)
            escaped = True
        elif character.isspace() or character in ";|&":
            flush()
        else:
            current.append(character)
    flush()
    return words


def _target_command_text(context: str) -> str:
    lines = context.splitlines()
    run_lines: list[str] = []
    for index, line in enumerate(lines):
        match = re.match(r"^(\s*)(?:-\s+)?run\s*:\s*(.*)$", line)
        if not match:
            continue
        value = match.group(2).strip()
        run_lines.append(value if value not in {"|", ">", "|-", ">-", "|+", ">+"} else "")
        key_indent = len(match.group(1))
        for next_line in lines[index + 1 :]:
            if next_line.strip() and _indent(next_line) <= key_indent:
                break
            if next_line.strip():
                run_lines.append(next_line.strip())
    return "\n".join(run_lines) if run_lines else context


def workflow_chart_targets(context: str, root: Path, chart_dirs: list[Path]) -> frozenset[str]:
    """Resolve only exact repository chart paths or rooted chart globs."""
    command_context = _target_command_text(context)
    working_dirs = _working_directories(context, root)
    targets: set[str] = set()
    chart_info = []
    for chart in chart_dirs:
        try:
            relative = chart.resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            continue
        chart_info.append((chart.name, relative))
    redirect_refs = re.findall(r'''(?:^|\s)(?:>>?|2>>?)\s*(['"]?[^\s'";&|]+)|\|\s*tee(?:\s+-a)?\s+(['"]?[^\s'";&|]+)''', command_context, re.IGNORECASE)
    destinations = [first or second for first, second in redirect_refs]
    if destinations:
        safe_destinations: set[str] = set()
        for destination in destinations:
            destination_norm = _normalize_path(destination, root)
            for name, relative in chart_info:
                exact = f"{relative}/Chart.yaml"
                if destination_norm == exact:
                    safe_destinations.add(name)
                for directory in working_dirs:
                    if _normalize_path(posixpath.join(directory, destination), root) == exact:
                        safe_destinations.add(name)
        if not safe_destinations or len(safe_destinations) != len(destinations):
            return frozenset()
    rooted_glob = bool(
        re.search(r"(?:^|[\s'\"])(?:\./)?deploy/charts/\*/Chart\.yaml(?:$|[\s'\";&|])", command_context)
        or re.search(r"(?:^|[\s'\"])(?:\./)?charts/\*/Chart\.yaml(?:$|[\s'\";&|])", command_context)
        and "deploy" in working_dirs
        or re.search(r"\bfind\s+(?:\./)?deploy/charts(?:/|\s)[^\n]*-(?:exec|execdir)\b[^\n]*\b(?:yq|sed|gsed|perl|python3?|ruby|awk)\b", command_context, re.IGNORECASE)
        or (
            "deploy" in working_dirs
            and re.search(r"\bfind\s+(?:\./)?charts(?:/|\s)[^\n]*-(?:exec|execdir)\b[^\n]*\b(?:yq|sed|gsed|perl|python3?|ruby|awk)\b", command_context, re.IGNORECASE)
        )
    )
    for ref in _path_refs(command_context):
        ref_norm = _normalize_path(ref, root)
        ref_matched = False
        for name, relative in chart_info:
            exact = f"{relative}/Chart.yaml"
            if ref_norm == exact:
                targets.add(name)
                ref_matched = True
            for directory in working_dirs:
                if _normalize_path(posixpath.join(directory, ref), root) == exact:
                    targets.add(name)
                    ref_matched = True
        if not ref_matched and not (
            rooted_glob and (ref == "Chart.yaml" or any(char in ref for char in "*?[]{}"))
        ):
            # A qualified external operand must never be masked by a second
            # bare operand or by a working-directory assumption.
            return frozenset()
    loop_root = bool(
        re.search(r"\bfor\s+[A-Za-z_][A-Za-z0-9_]*\s+in\s+(?:\./)?deploy/charts/\*", command_context)
        or (re.search(r"\bfor\s+[A-Za-z_][A-Za-z0-9_]*\s+in\s+(?:\./)?charts/\*", command_context) and "deploy" in working_dirs)
    )
    if rooted_glob or loop_root:
        targets.update(name for name, _ in chart_info)
    return frozenset(targets)


def _quote_at(text: str, index: int) -> str | None:
    quote = None
    escaped = False
    for character in text[:index]:
        if escaped:
            escaped = False
        elif character == "\\":
            escaped = True
        elif character in {"'", '"'}:
            quote = None if quote == character else (character if quote is None else quote)
    return quote


def _shell_segments(text: str) -> list[str]:
    """Split a run block at simple shell command boundaries.

    This is deliberately not a shell interpreter. It only gives the audit a
    conservative way to distinguish an executable command from a tool name
    mentioned inside ``echo``/``printf`` text.
    """
    segments: list[str] = []
    current: list[str] = []
    quote: str | None = None
    escaped = False

    def flush() -> None:
        value = "".join(current).strip()
        if value:
            segments.append(value)
        current.clear()

    index = 0
    while index < len(text):
        character = text[index]
        if escaped:
            current.append(character)
            escaped = False
            index += 1
            continue
        if quote:
            current.append(character)
            if character == quote:
                quote = None
            elif character == "\\" and quote == '"':
                escaped = True
            index += 1
            continue
        if character in {"'", '"'}:
            quote = character
            current.append(character)
            index += 1
            continue
        if character == "\\":
            current.append(character)
            escaped = True
            index += 1
            continue
        if character in {";", "\n", "|", "&"}:
            flush()
            index += 1
            while index < len(text) and text[index] in "|&; ":
                index += 1
            continue
        current.append(character)
        index += 1
    flush()
    return segments


def _command_name(segment: str) -> str:
    """Return the first executable word for a simple command segment."""
    value = segment.strip()
    # Shell control words can precede a branch command after splitting ``;``.
    value = re.sub(r"^(?:(?:then|else|do)\b\s*)+", "", value, flags=re.IGNORECASE)
    if re.match(r"^(?:if|elif|for|while|until|case|function|select)\b", value, re.IGNORECASE):
        return ""
    value = re.sub(r"^(?:[A-Za-z_][A-Za-z0-9_]*=(?:'[^']*'|\"[^\"]*\"|[^\s]+)\s+)+", "", value)
    if value.startswith("command "):
        value = value[8:].lstrip()
    match = re.match(r"([^\s;&|]+)", value)
    if not match:
        return ""
    token = match.group(1)
    if token[:1] in {"'", '"'}:
        return ""
    return posixpath.basename(token)


def _actual_mutation_segments(command: str) -> list[str]:
    tools = {"sed", "gsed", "yq", "perl", "python", "python3", "ruby", "awk", "tee"}
    result = []
    for segment in _shell_segments(command):
        if not re.search(r"\bappVersion\b", segment, re.IGNORECASE):
            continue
        if _command_name(segment).lower() in tools:
            result.append(segment)
    return result


def _has_option(segment: str, options: set[str]) -> bool:
    for token in _shell_words(segment):
        clean = token.strip("'\"")
        if clean in options:
            return True
        if any(clean.startswith(option + ".") for option in options if option == "-i"):
            return True
    return False


def _is_local_script(segment: str) -> bool:
    words = _shell_words(segment)
    if not words:
        return False
    first = words[0].strip("'\"")
    if first.startswith("./") or first.startswith("/"):
        return first.endswith((".sh", ".bash"))
    if posixpath.basename(first) in {"bash", "sh"}:
        return any(
            token.strip("'\"").endswith((".sh", ".bash"))
            and (token.strip("'\"").startswith("./") or token.strip("'\"").startswith("/"))
            for token in words[1:]
        )
    return False


def _read_delimited(text: str, start: int, delimiter: str) -> tuple[str, int] | None:
    value = []
    escaped = False
    index = start
    while index < len(text):
        character = text[index]
        if escaped:
            value.append("\\" + character)
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == delimiter:
            return "".join(value), index + 1
        else:
            value.append(character)
        index += 1
    return None


def _sed_values(command: str) -> list[tuple[str, bool]]:
    values = []
    for match in re.finditer(r"(?<![A-Za-z0-9])s(?P<delimiter>[^A-Za-z0-9\s])", command):
        delimiter = match.group("delimiter")
        pattern = _read_delimited(command, match.end(), delimiter)
        if pattern is None:
            continue
        replacement = _read_delimited(command, pattern[1], delimiter)
        if replacement is None or "appVersion" not in pattern[0]:
            continue
        values.append((replacement[0], _quote_at(command, match.start()) != "'"))
    return values


def _strip_value_comment(value: str) -> str:
    """Remove a shell/yq comment without truncating ``${VAR#prefix}``."""
    quote: str | None = None
    escaped = False
    braces = 0
    for index, character in enumerate(value):
        if escaped:
            escaped = False
            continue
        if quote:
            if character == quote:
                quote = None
            elif character == "\\" and quote == '"':
                escaped = True
            continue
        if character in {"'", '"'}:
            quote = character
        elif character == "{":
            braces += 1
        elif character == "}" and braces:
            braces -= 1
        elif character == "#" and braces == 0:
            return value[:index].rstrip()
    return value.strip()


def _first_expression_rhs(value: str) -> str:
    """Return the first yq assignment expression before a top-level pipe."""
    quote: str | None = None
    escaped = False
    depth = 0
    for index, character in enumerate(value):
        if escaped:
            escaped = False
            continue
        if quote:
            if character == quote:
                quote = None
            elif character == "\\" and quote == '"':
                escaped = True
            continue
        if character in {"'", '"'}:
            quote = character
        elif character in "([{":
            depth += 1
        elif character in ")]}":
            depth = max(0, depth - 1)
        elif character == "|" and depth == 0:
            return value[:index].rstrip()
    return value.strip()


def _mask_quoted_literals(value: str) -> str:
    result = list(value)
    quote: str | None = None
    escaped = False
    for index, character in enumerate(value):
        if escaped:
            result[index] = " "
            escaped = False
            continue
        if quote:
            result[index] = " "
            if character == quote:
                quote = None
            elif character == "\\" and quote == '"':
                escaped = True
            continue
        if character in {"'", '"'}:
            result[index] = " "
            quote = character
    return "".join(result)


def _yq_values(command: str) -> list[tuple[str, bool]]:
    values: list[tuple[str, bool]] = []
    for segment in _actual_mutation_segments(command):
        if _command_name(segment).lower() != "yq":
            continue
        assignment = re.search(r"\.appVersion\s*=", segment, re.IGNORECASE)
        if not assignment:
            continue
        quote_start = None
        quote = None
        # Find the quoted yq filter containing the assignment. A quoted
        # filter is the normal, unambiguous yq form.
        for index, character in enumerate(segment):
            if character not in {"'", '"'}:
                continue
            end = index + 1
            escaped = False
            while end < len(segment):
                current = segment[end]
                if escaped:
                    escaped = False
                elif current == "\\" and character == '"':
                    escaped = True
                elif current == character:
                    break
                end += 1
            if assignment.start() > index and assignment.start() < end:
                quote_start, quote = index, character
                expression = segment[index + 1 : end]
                values.append((_strip_value_comment(expression), quote != "'"))
                break
        if quote_start is None:
            tail = segment[assignment.end() :]
            tail = re.split(r"\s+(?:['\"]?(?:\./)?[^\s'\"]+/)?Chart\.yaml\b", tail, maxsplit=1, flags=re.IGNORECASE)[0]
            values.append((_strip_value_comment(tail), True))
    return values


def _mutation_values(command: str) -> list[tuple[str, bool]]:
    values = []
    for segment in _actual_mutation_segments(command):
        name = _command_name(segment).lower()
        if name in {"sed", "gsed"}:
            values.extend(_sed_values(segment))
    values.extend(_yq_values(command))
    if not values:
        for segment in _actual_mutation_segments(command):
            name = _command_name(segment).lower()
            if name in {"python", "python3", "ruby", "perl", "awk", "tee"}:
                for match in re.finditer(r"\bappVersion\s*[:=]\s*([^\n;]+)", segment, re.IGNORECASE):
                    values.append((match.group(1), True))
                if not values:
                    for match in re.finditer(r"(?:replace|sub|write_text|open)\s*\(([^\n]+)", segment, re.IGNORECASE):
                        values.append((match.group(1), True))
    return values


def workflow_app_version_mutation(command: str) -> bool:
    """Require a tool invocation that writes the resulting file, not stdout only."""
    for segment in _actual_mutation_segments(command):
        name = _command_name(segment).lower()
        if name in {"sed", "gsed"}:
            if _has_option(segment, {"-i", "--in-place"}):
                return True
            if re.search(r"(?:>|>>)\s*(?:['\"]?(?:\./)?[^\s'\";&|]+/)?Chart\.yaml\b(?![A-Za-z0-9_.-])", segment, re.IGNORECASE):
                return True
            if re.search(r"\|\s*tee(?:\s+-a)?\s+(?:['\"]?(?:\./)?[^\s'\";&|]+/)?Chart\.yaml\b(?![A-Za-z0-9_.-])", command, re.IGNORECASE):
                return True
        elif name == "yq" and _has_option(segment, {"-i", "--inplace"}):
            return True
        elif name == "perl" and any(re.match(r"-[a-z]*i[a-z]*$", token.strip("'\""), re.IGNORECASE) for token in _shell_words(segment)):
            return True
        elif name in {"python", "python3", "ruby"} and re.search(r"write_text\s*\(|open\s*\([^\n]+['\"]w|(?:>|>>)\s*[^\n;&|]*Chart\.yaml\b|\btee\b[^\n]*Chart\.yaml\b", segment, re.IGNORECASE):
            return True
        elif name == "awk" and re.search(r">>?(?:\s*['\"]?[^\n;&|]*Chart\.yaml\b)", segment, re.IGNORECASE):
            return True
        elif name == "tee" and re.search(r"Chart\.yaml\b", segment, re.IGNORECASE):
            return True
    return False


def _source_kinds_for_value(value: str, shell_expand: bool = True) -> tuple[bool, bool]:
    value = _strip_value_comment(value).strip()
    # A yq filter is often passed as ``.appVersion = <rhs>``. Only the RHS
    # can establish the value; comments, filenames and unrelated command text
    # must not taint it.
    rhs_match = re.search(r"\.appVersion\s*=\s*(.*)$", value, re.IGNORECASE | re.DOTALL)
    if not rhs_match:
        rhs_match = re.search(r"\bappVersion\s*:\s*(.*)$", value, re.IGNORECASE | re.DOTALL)
    rhs = rhs_match.group(1).strip() if rhs_match else value
    rhs = _strip_value_comment(rhs).strip()
    rhs = _first_expression_rhs(rhs)
    while len(rhs) >= 2 and rhs[0] == "(" and rhs[-1] == ")":
        rhs = rhs[1:-1].strip()
    tag = False
    sha = False

    tag_expression = re.compile(r"\$\{\{\s*github\.(?:ref_name|event\.release\.tag_name)\s*\}\}", re.IGNORECASE)
    sha_expression = re.compile(r"\$\{\{\s*github\.sha\s*\}\}", re.IGNORECASE)
    tag_function = re.compile(r"^(?:strenv|env)\(\s*(?:GITHUB_REF_NAME|github\.ref_name|github\.event\.release\.tag_name)\s*\)$", re.IGNORECASE)
    sha_function = re.compile(r"(?:strenv|env)\(\s*(?:GITHUB_SHA|github\.sha)\s*\)", re.IGNORECASE)
    tag_shell = re.compile(r"^\$(?:\{GITHUB_REF_NAME\}|GITHUB_REF_NAME)$")
    sha_shell = re.compile(r"\$(?:\{GITHUB_SHA\}|GITHUB_SHA)(?![A-Za-z0-9_])")
    tag_ref_strip = re.compile(r"^\$\{GITHUB_REF(?:#|##)refs/tags/\}$")
    tag_replace = re.compile(r"^github\.ref\s*\.\s*replace\(\s*['\"]refs/tags/['\"]\s*,\s*['\"]['\"]\s*\)$", re.IGNORECASE)

    # Strip a pair of quotes used only to carry a shell value. Do not strip
    # quoted literals that contain a prefix/suffix around the source.
    unquoted = rhs
    if not re.search(r"\.appVersion\s*=", value, re.IGNORECASE) and len(unquoted) >= 2 and unquoted[0] == unquoted[-1] and unquoted[0] in {"'", '"'}:
        unquoted = unquoted[1:-1].strip()
    if tag_function.fullmatch(unquoted) or tag_replace.fullmatch(unquoted):
        tag = True
    if shell_expand and (tag_shell.fullmatch(unquoted) or tag_ref_strip.fullmatch(unquoted) or tag_expression.fullmatch(unquoted)):
        tag = True
    masked = _mask_quoted_literals(unquoted)
    if sha_function.search(masked) or sha_expression.search(masked):
        sha = True
    if shell_expand and sha_shell.search(rhs):
        sha = True
    if shell_expand and re.search(r"\$\{GITHUB_REF(?:#|##)refs/tags/\}", rhs):
        tag = True
    if tag_replace.search(masked):
        tag = True
    if re.search(r"\b(?:os\.environ(?:\.get)?|os\.getenv|process\.env)\s*(?:\[|\(\s*['\"])\s*['\"]?GITHUB_REF_NAME", masked, re.IGNORECASE):
        tag = True
    if re.search(r"\b(?:os\.environ(?:\.get)?|os\.getenv|process\.env)\s*(?:\[|\(\s*['\"])\s*['\"]?GITHUB_SHA", masked, re.IGNORECASE):
        sha = True
    if re.search(r"\bgit\s+rev-parse(?:\s+--verify)?\s+HEAD\b", masked, re.IGNORECASE):
        sha = True
    return tag, sha


def source_kinds(text: str) -> tuple[bool, bool]:
    """Return direct, exact release identity sources found in text."""
    return _source_kinds_for_value(text, True)


def _aliases(context: str) -> dict[str, tuple[bool, bool]]:
    aliases: dict[str, tuple[bool, bool]] = {}
    # Only known workflow mapping levels are considered. In particular,
    # ``with: { env: ... }`` is an action input, not an Actions environment.
    for block in _mapping_blocks(context, "env", {0, 4, 6, 8}):
        for line in block.splitlines()[1:]:
            match = re.match(r"^\s*([A-Z][A-Z0-9_]*)\s*:\s*(.*)$", line)
            if match:
                aliases[match.group(1)] = _source_kinds_for_value(match.group(2), True)
    lines = context.splitlines()
    for line in lines:
        unset = re.match(r"^\s*unset\s+([A-Z][A-Z0-9_]*)", line)
        if unset:
            aliases.pop(unset.group(1), None)
            continue
        match = re.match(r"^\s*(?:export\s+)?([A-Z][A-Z0-9_]*)\s*=\s*(.*)$", line)
        if match:
            rhs = match.group(2)
            stripped = rhs.strip()
            aliases[match.group(1)] = _source_kinds_for_value(
                stripped,
                not (stripped.startswith("'") and stripped.endswith("'")),
            )
    return aliases


def _mapping_blocks(text: str, key: str, indents: set[int]) -> list[str]:
    """Extract mapping blocks at known YAML structural indentation levels."""
    lines = text.splitlines()
    blocks: list[str] = []
    for index, line in enumerate(lines):
        match = re.match(r"^( *)(?:-\s+)?" + re.escape(key) + r"\s*:\s*(.*)$", line, re.IGNORECASE)
        if not match or len(match.group(1)) not in indents:
            continue
        base = len(match.group(1))
        # Walk outward through preceding mappings so an ``env`` nested under
        # an action's ``with`` input cannot be mistaken for a real env block.
        under_with = False
        for previous in reversed(lines[:index]):
            if not previous.strip() or _indent(previous) >= base:
                continue
            if re.match(r"^\s*(?:-\s+)?with\s*:", previous, re.IGNORECASE):
                under_with = True
            break
        if under_with:
            continue
        block = [line]
        for child in lines[index + 1 :]:
            if child.strip() and _indent(child) <= base:
                break
            block.append(child)
        blocks.append("\n".join(block))
    return blocks


def workflow_source_kinds(command: str, context: str) -> tuple[bool, bool]:
    """Trace only values used by the appVersion mutation RHS."""
    if re.search(r"\$\{\{\s*github\.(?:ref_name|event\.release\.tag_name|sha)\s*\}\}", command, re.IGNORECASE):
        return False, False
    tag = sha = False
    # Callers normally pass only effective env mappings. If a legacy caller
    # passes a full step context, remove the command suffix so assignments
    # after a mutation cannot retroactively taint its value.
    base_context = context
    command_index = context.find(command)
    if command_index >= 0:
        base_context = context[:command_index]
    segments = _shell_segments(command)
    cursor = 0
    for segment in segments:
        position = command.find(segment, cursor)
        if position < 0:
            position = cursor
        cursor = position + len(segment)
        if segment not in _actual_mutation_segments(command):
            continue
        prefix = "\n".join(_shell_segments(command[:position]))
        leading = re.match(r"^((?:[A-Za-z_][A-Za-z0-9_]*=(?:'[^']*'|\"[^\"]*\"|[^\s]+)\s+)+)", segment)
        leading_context = leading.group(1) if leading else ""
        aliases = _aliases(base_context + "\n" + prefix + "\n" + leading_context)
        values = _mutation_values(segment)
        for value, shell_expand in values:
            direct_tag, direct_sha = _source_kinds_for_value(value, shell_expand)
            tag, sha = tag or direct_tag, sha or direct_sha
            variables = re.findall(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))|\b(?:strenv|env)\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)", value)
            for first, second, third in variables:
                alias = aliases.get(first or second or third)
                if alias:
                    tag, sha = tag or alias[0], sha or alias[1]
    return tag, sha


def _tag_guard(text: str) -> bool:
    if "||" in text:
        return False
    if re.search(r"(?:['\"]?\$?(?:github\.ref_type|GITHUB_REF_TYPE)['\"]?\s*(?:==|(?<![!<>])=)\s*['\"]?tag\b)", text, re.IGNORECASE):
        return True
    for match in re.finditer(r"\bstartsWith\s*\(([^\n]*)", text, re.IGNORECASE):
        prefix = text[max(0, match.start() - 12) : match.start()]
        if re.search(r"!\s*$", prefix):
            continue
        if re.search(r"refs/tags/", match.group(1), re.IGNORECASE):
            return True
    return bool(re.search(r"\bGITHUB_REF\b[^\n]*(?:==|(?<![!<>])=)[^\n]*refs/tags/", text, re.IGNORECASE))


def _sha_guard(text: str) -> bool:
    if "||" in text:
        return False
    return bool(
        re.search(r"(?:['\"]?\$?(?:github\.ref_type|GITHUB_REF_TYPE)['\"]?\s*!=\s*['\"]?tag\b)", text, re.IGNORECASE)
        or re.search(r"!\s*startsWith\s*\([^\n]*refs/tags/", text, re.IGNORECASE)
        or re.search(r"\bGITHUB_REF_TYPE\b[^\n]*(?:!=|(?<![!<>])=)\s*['\"]?(?:branch|non[-_ ]?tag)", text, re.IGNORECASE)
    )


def _shell_guard_profile(command: str) -> str:
    if_pos = re.search(r"\bif\b", command, re.IGNORECASE)
    if not if_pos:
        return "unconditional"
    if len(command) > 20000:
        return "invalid"
    then_pos = re.search(r"\bthen\b", command[if_pos.end() :], re.IGNORECASE)
    if not then_pos:
        return "invalid"
    then_start = if_pos.end() + then_pos.end()
    else_pos = re.search(r"\belse\b", command[then_start:], re.IGNORECASE)
    fi_pos = re.search(r"\bfi\b", command[then_start:], re.IGNORECASE)
    if not fi_pos:
        return "invalid"
    fi_start = then_start + fi_pos.start()
    if not else_pos or then_start + else_pos.start() > fi_start:
        return "invalid"
    else_start = then_start + else_pos.end()
    condition = command[if_pos.end() : if_pos.end() + then_pos.start()]
    then_text = command[then_start : then_start + else_pos.start()]
    else_text = command[else_start:fi_start]
    then_tag, then_sha = workflow_source_kinds(then_text, "")
    else_tag, else_sha = workflow_source_kinds(else_text, "")
    if _tag_guard(condition) and then_tag and else_sha:
        return "mixed"
    if _sha_guard(condition) and then_sha and else_tag:
        return "mixed"
    # An ``if`` block that is not the recognized tag/non-tag pair is not
    # evidence of a deterministic write. Treat it as invalid rather than
    # silently promoting it to an unconditional mutation.
    return "invalid"


def workflow_guard_profile(command: str, step_condition: str = "", job_condition: str = "") -> str:
    conditions = [condition.strip() for condition in (step_condition, job_condition) if condition.strip()]
    profiles = []
    for condition in conditions:
        # A disjunction can make a supposedly tag/sha-specific write execute
        # on the opposite ref. We do not attempt to prove arbitrary boolean
        # expressions with this small parser.
        if "||" in condition:
            return "invalid"
        if re.search(r"\b(?:false|always|cancelled|failure)\b", condition, re.IGNORECASE):
            return "invalid"
        tag = _tag_guard(condition)
        sha = _sha_guard(condition)
        if tag and sha:
            return "invalid"
        if tag:
            profiles.append("tag")
        elif sha:
            profiles.append("sha")
        elif re.fullmatch(r"(?:true|success\s*\(\)|\$\{\{\s*success\s*\(\)\s*\}\})", condition, re.IGNORECASE):
            profiles.append("unconditional")
        else:
            return "invalid"
    if "tag" in profiles and "sha" in profiles:
        return "invalid"
    tag = "tag" in profiles
    sha = "sha" in profiles
    shell = _shell_guard_profile(command)
    if shell in {"mixed", "invalid"}:
        return shell
    if tag and sha:
        return "mixed"
    if tag:
        return "tag"
    if sha:
        return "sha"
    return "unconditional"


def workflow_job_packaging_lines(job: WorkflowJob) -> list[int]:
    lines: list[int] = []
    if not job.steps and re.search(r"^ {4}uses\s*:\s*['\"]?[^\n]*(?:package|publish|release|cluster)", job.text, re.IGNORECASE | re.MULTILINE):
        return [job.start_line]
    for step in job.steps:
        context = "\n".join((step.command, step.working_directory or ""))
        command = step.command or step.text
        metadata = "\n".join(line for line in step.text.splitlines() if not re.match(r"^\s*(?:-\s+)?name\s*:", line, re.IGNORECASE))
        executable_segments = _shell_segments(command)
        # A repository-local script can package or mutate the chart in ways
        # this read-only parser cannot inspect. Treat it as a package boundary
        # so a later explicit stamp cannot mask an earlier hidden build.
        if any(_is_local_script(segment) for segment in executable_segments):
            lines.append(step.start_line)
            continue
        if any(
            _command_name(segment).lower() == "helm"
            and re.search(r"\bpackage\b(?!\s+--help\b)", segment, re.IGNORECASE)
            for segment in executable_segments
        ) or any(
            _command_name(segment).lower() == "sealos"
            and re.search(r"\bbuild\b(?!\s+--help\b)", segment, re.IGNORECASE)
            for segment in executable_segments
        ):
            lines.append(step.start_line)
            continue
        action_build = bool(re.search(r"^\s*(?:-\s+)?uses\s*:\s*['\"]?docker/build-push-action@", metadata, re.IGNORECASE | re.MULTILINE))
        if any(
            _command_name(segment).lower() == "docker"
            and re.search(r"\bdocker(?:\s+buildx)?\s+build\b", segment, re.IGNORECASE)
            for segment in executable_segments
        ) or action_build:
            build_context = "\n".join((context, metadata)) if action_build else context
            if re.search(r"(?:^|[\s/'\"])(?:\./)?deploy(?:/|[\s'\"]|$)|\bcluster\b|-cluster", build_context, re.IGNORECASE):
                lines.append(step.start_line)
                continue
        if any(
            _command_name(segment).lower() == "docker"
            and re.search(r"\bdocker\s+(?:buildx\s+)?(?:imagetools|manifest)\s+create\b", segment, re.IGNORECASE)
            for segment in executable_segments
        ) and re.search(r"\bcluster\b|-cluster|deploy/", context, re.IGNORECASE):
            lines.append(step.start_line)
            continue
        if any(
            (
                _command_name(segment).lower() == "make"
                and re.search(r"\b(?:package|release|cluster|build)\b", segment, re.IGNORECASE)
            )
            or (
                _command_name(segment).lower() in {"npm", "pnpm"}
                and re.search(r"\b(?:package|release|build:cluster)\b", segment, re.IGNORECASE)
            )
            or (
                _command_name(segment).lower() in {"bash", "sh"}
                and re.search(r"\b(?:package|release|cluster|ship|build)[^\s/]*\.?(?:sh|bash)?\b", segment, re.IGNORECASE)
            )
            or re.search(r"(?:^|/)\b(?:package|release|cluster|ship|build)[^\s/]*\.(?:sh|bash)\b", segment, re.IGNORECASE)
            for segment in executable_segments
        ):
            lines.append(step.start_line)
            continue
        if re.search(r"^\s*(?:-\s+)?uses\s*:\s*['\"]?[^\n]*(?:package|publish|release|cluster)", metadata, re.IGNORECASE | re.MULTILINE):
            lines.append(step.start_line)
    return sorted(set(lines))


def workflow_path_is_safe(job: WorkflowJob) -> bool:
    """Return whether a job can be relied on for a successful package path."""
    conditions = [job.condition] + [step.condition for step in job.steps]
    for condition in conditions:
        if not condition:
            continue
        if re.search(r"\b(?:always|failure|cancelled|false)\b", condition, re.IGNORECASE):
            return False
        if workflow_guard_profile("", condition, "") == "invalid":
            return False
    for line in job.text.splitlines():
        match = re.match(r"^\s*(?:-\s*)?continue-on-error\s*:\s*(.*?)\s*$", line, re.IGNORECASE)
        if match and match.group(1).strip().lower() not in {"false", "${{ false }}"}:
            return False
    for step in job.steps:
        if re.search(r"\|\|\s*(?:true|:)\b|\bset\s*\+e\b", step.command, re.IGNORECASE):
            return False
        if re.search(r"\bif\b", step.command, re.IGNORECASE) and workflow_guard_profile(step.command, step.condition, job.condition) == "invalid":
            return False
    return True


def workflow_release_candidate(path: Path, text: str) -> bool:
    jobs = workflow_jobs(path, text)
    if any(workflow_job_packaging_lines(job) for job in jobs):
        return True
    if jobs:
        # A workflow with parsed jobs is a candidate only when an executable
        # build/package command (or a reusable packaging action) is present.
        for job in jobs:
            for step in job.steps:
                if re.search(r"^\s*(?:-\s+)?uses\s*:\s*['\"]?(?:[^\n]*)(?:package|publish|release|cluster)", step.text, re.IGNORECASE | re.MULTILINE):
                    return True
                for segment in _shell_segments(step.command):
                    name = _command_name(segment).lower()
                    if name in {"docker", "helm", "sealos", "make", "npm", "pnpm", "bash", "sh"} and re.search(r"\b(?:build|package|release|cluster|publish)\b", segment, re.IGNORECASE):
                        return True
                    if _is_local_script(segment):
                        return True
        return False
    command_text = _target_command_text(text)
    build = any(
        _command_name(segment).lower() in {"docker", "helm", "sealos", "make", "npm", "pnpm", "bash", "sh"}
        and re.search(r"\b(?:build|package|release|cluster|publish)\b", segment, re.IGNORECASE)
        for segment in _shell_segments(command_text)
    )
    context = re.search(r"\b(?:deploy|cluster|sealos|helm)\b|^[ \t]*(?:tags|release)[ \t]*:", text, re.IGNORECASE | re.MULTILINE)
    return bool(build and (context or path.stem.lower() in {"release", "publish"}))


def _job_default_workdir(job_text: str) -> str | None:
    match = re.search(r"(?ms)^\s{4}defaults\s*:\s*\n\s{6}run\s*:\s*\n\s{8}working-directory\s*:\s*([^\s#]+)", job_text)
    return match.group(1).strip("'\"") if match else None


def _workflow_default_workdir(text: str) -> str | None:
    match = re.search(r"(?ms)^defaults\s*:\s*\n\s{2}run\s*:\s*\n\s{4}working-directory\s*:\s*([^\s#]+)", text)
    return match.group(1).strip("'\"") if match else None


def workflow_app_version_writes(path: Path, text: str, root: Path, chart_dirs: list[Path]) -> list[WorkflowAppVersionWrite]:
    writes: list[WorkflowAppVersionWrite] = []
    workflow_env = "\n".join(_mapping_blocks(text, "env", {0}))
    for job in workflow_jobs(path, text):
        package_lines = workflow_job_packaging_lines(job)
        first_package = min(package_lines, default=None)
        default_workdir = _job_default_workdir(job.text) or _workflow_default_workdir(text)
        job_env = "\n".join(_mapping_blocks(job.text, "env", {4}))
        for step in job.steps:
            command = step.command
            if not command or not workflow_app_version_mutation(command):
                continue
            target_context = "\n".join(
                part
                for part in (
                    command,
                    f"working-directory: {step.working_directory}" if step.working_directory else "",
                    f"working-directory: {default_workdir}" if default_workdir and not step.working_directory else "",
                )
                if part
            )
            step_env = "\n".join(_mapping_blocks(step.text, "env", {6, 8}))
            # Only effective workflow/job/step env mappings and the command
            # itself participate in provenance. Action inputs, names, and
            # arbitrary step metadata must not create aliases.
            context = "\n".join(part for part in (workflow_env, job_env, step_env) if part)
            targets = workflow_chart_targets(target_context, root, chart_dirs)
            if not targets:
                continue
            tag, sha = workflow_source_kinds(command, context)
            guard = workflow_guard_profile(command, step.condition, job.condition)
            writes.append(WorkflowAppVersionWrite(path, step.start_line, targets, tag, sha, first_package is None or step.start_line < first_package, job.job_id, guard))
    return writes


def workflow_cluster_packaging_lines(lines: list[str]) -> list[int]:
    """Compatibility helper used by callers that only have raw workflow lines."""
    text = "\n".join(lines)
    jobs = workflow_jobs(Path("workflow.yaml"), text)
    if jobs:
        return sorted(line for job in jobs for line in workflow_job_packaging_lines(job))
    return [index + 1 for index, line in enumerate(lines) if re.search(r"\b(?:helm\s+package|sealos\s+build)\b|\bcluster\b.*\b(?:docker|helm)\b", line, re.IGNORECASE)]


def workflow_reachable_jobs(jobs: tuple[WorkflowJob, ...], job_id: str) -> frozenset[str]:
    by_id = {job.job_id: job for job in jobs}
    reachable: set[str] = set()
    pending = list(by_id.get(job_id, WorkflowJob(Path("."), job_id, 0, 0, "", frozenset(), "", ())).needs)
    while pending:
        candidate = pending.pop()
        if candidate in reachable:
            continue
        reachable.add(candidate)
        pending.extend(by_id.get(candidate, WorkflowJob(Path("."), candidate, 0, 0, "", frozenset(), "", ())).needs)
    return frozenset(reachable)
