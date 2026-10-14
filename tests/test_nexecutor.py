"""Exercise the session wire protocol without a server or cloud resources."""

import asyncio
import json

import httpx
import pytest

from llmpuffin.runtime import nexecutor as nx


def session(**overrides):
    return {
        "id": "ss-test",
        "observation_incarnation": "inc-1",
        "status": "running",
        "image": "audit:latest",
        **overrides,
    }


def receipt(**overrides):
    return {
        "id": "ex-test",
        "session_id": "ss-test",
        "status": "completed",
        "exit_code": 0,
        "stdout": "hello\n",
        "stderr": "",
        "output_truncated": False,
        **overrides,
    }


@pytest.fixture
def transport(monkeypatch):
    original_async = httpx.AsyncClient
    original_sync = httpx.Client
    monkeypatch.setattr(nx, "_POLL_INTERVAL", 0)

    def install(handler):
        mock = httpx.MockTransport(handler)
        monkeypatch.setattr(
            nx.httpx, "AsyncClient", lambda **kw: original_async(transport=mock, **kw)
        )
        monkeypatch.setattr(
            nx.httpx, "Client", lambda **kw: original_sync(transport=mock, **kw)
        )

    return install


def runtime(token=""):
    return nx.NexecutorRuntime(
        "audit:latest", "/src", "https://nx.test", token, "ss-test", "inc-1"
    )


def test_start_poll_reuse_and_stop(transport):
    requests = []
    polls = 0

    def handle(req):
        nonlocal polls
        requests.append(req)
        if req.url.path == "/v1/sessions":
            assert json.loads(req.content)["backend"] == "k8s"
            return httpx.Response(202, json=session(status="creating"))
        if req.url.path.endswith("/stop"):
            return httpx.Response(202, json=session(status="stopping"))
        polls += 1
        return httpx.Response(
            200, json=session(status="starting" if polls == 1 else "running")
        )

    transport(handle)

    async def run():
        rt = await nx.NexecutorRuntime.start(
            "audit:latest", "/src", "https://nx.test", backend="k8s"
        )
        assert rt.container_id == "ss-test"
        await rt.astop()
        assert rt._heartbeat_task.cancelling()
        # Resuming attaches to the same workspace and never creates another.
        resumed = await nx.NexecutorRuntime.start(
            "audit:latest", "/src", "https://nx.test", container_id="ss-test"
        )
        resumed.__exit__(None, None, None)

    asyncio.run(run())
    assert (
        sum(r.method == "POST" and r.url.path == "/v1/sessions" for r in requests) == 1
    )
    assert all("/workloads" not in r.url.path for r in requests)


def test_exec_polls_preserving_argv_workdir_exit_and_streams(transport):
    requests = []
    command = ["sh", "-c", "printf '%s' '$literal'", ""]

    def handle(req):
        requests.append(req)
        if req.method == "POST":
            body = json.loads(req.content)
            assert body["command"] == command
            assert body["workdir"] == "/src/with spaces"
            assert body["timeout_seconds"] == 77
            assert body["session_incarnation"] == "inc-1"
            assert body["idempotency_key"]
            return httpx.Response(202, json=receipt(status="running", exit_code=None))
        return httpx.Response(200, json=receipt(exit_code=42, stderr="failure\n"))

    transport(handle)
    result = asyncio.run(
        runtime().exec(command, timeout=77, workdir="/src/with spaces")
    )
    assert (result.command, result.exit_code, result.stdout, result.stderr) == (
        command,
        42,
        "hello\n",
        "failure\n",
    )
    assert [r.method for r in requests] == ["POST", "GET"]


@pytest.mark.parametrize("failure", ["disconnect", "server_error", "invalid_json"])
def test_lost_post_response_recovers_by_key_without_resubmitting(transport, failure):
    submissions = []

    def handle(req):
        if req.method == "POST":
            submissions.append(json.loads(req.content))
            if failure == "disconnect":
                raise httpx.ReadError("lost response", request=req)
            if failure == "invalid_json":
                return httpx.Response(202, content=b"broken")
            return httpx.Response(503)
        assert req.url.path.endswith(
            "/executions-by-idempotency-key/" + submissions[0]["idempotency_key"]
        )
        return httpx.Response(200, json=receipt())

    transport(handle)
    assert asyncio.run(runtime().exec(["echo", "hello"])).ok
    assert len(submissions) == 1


def test_missing_recovery_receipt_never_replays_and_stops_session(transport):
    posts = []

    def handle(req):
        if req.method == "POST":
            posts.append(req.url.path)
            if req.url.path.endswith("/stop"):
                return httpx.Response(202, json=session(status="stopping"))
            raise httpx.ReadError("lost response", request=req)
        return httpx.Response(404)

    transport(handle)
    with pytest.raises(RuntimeError, match="outcome is unknown"):
        asyncio.run(runtime().exec(["side-effect"]))
    assert posts == ["/v1/sessions/ss-test/executions", "/v1/sessions/ss-test/stop"]


@pytest.mark.parametrize("status", [404, 409, 403])
def test_explicit_exec_errors_do_not_recreate_or_replay(transport, status):
    paths = []

    def handle(req):
        paths.append(req.url.path)
        return (
            httpx.Response(202, json=session())
            if req.url.path.endswith("/stop")
            else httpx.Response(status)
        )

    transport(handle)
    with pytest.raises(httpx.HTTPStatusError):
        asyncio.run(runtime().exec(["write-file"]))
    assert paths == ["/v1/sessions/ss-test/executions", "/v1/sessions/ss-test/stop"]


def test_refreshes_rotating_token_on_unauthorized(transport, tmp_path):
    token = tmp_path / "token"
    token.write_text("old")
    auth = []

    def handle(req):
        auth.append(req.headers["authorization"])
        if len(auth) == 1:
            token.write_text("new")
            return httpx.Response(401)
        return httpx.Response(202, json=receipt())

    transport(handle)
    assert asyncio.run(runtime(str(token)).exec(["true"])).ok
    assert auth == ["Bearer old", "Bearer new"]


@pytest.mark.parametrize(
    "values,error",
    [
        ({"status": "timed_out", "exit_code": 124}, TimeoutError),
        ({"status": "unknown", "exit_code": None}, RuntimeError),
        ({"output_truncated": True}, RuntimeError),
        ({"exit_code": None}, RuntimeError),
        ({"session_id": "ss-other"}, RuntimeError),
    ],
)
def test_honest_terminal_errors(transport, values, error):
    def handle(req):
        return httpx.Response(
            202, json=session() if req.url.path.endswith("/stop") else receipt(**values)
        )

    transport(handle)
    with pytest.raises(error):
        asyncio.run(runtime().exec(["true"]))


def test_polling_retries_transient_get_errors_only(transport):
    calls = []

    def handle(req):
        calls.append(req.method)
        if req.method == "POST":
            return httpx.Response(202, json=receipt(status="running", exit_code=None))
        if len(calls) < 4:
            return httpx.Response(503)
        return httpx.Response(200, json=receipt())

    transport(handle)
    assert asyncio.run(runtime().exec(["true"])).ok
    assert calls == ["POST", "GET", "GET", "GET"]


def test_cancellation_stops_session(transport):
    paths = []
    started = asyncio.Event()

    async def handle(req):
        paths.append(req.url.path)
        if req.url.path.endswith("/stop"):
            return httpx.Response(202, json=session(status="stopping"))
        started.set()
        await asyncio.Event().wait()

    transport(handle)

    async def run():
        rt = runtime()
        task = asyncio.create_task(rt.exec(["long-running"]))
        await started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert rt._stopped

    asyncio.run(run())
    assert paths[-1].endswith("/stop")


def test_start_recovery_and_changed_history(transport):
    calls = []

    def handle(req):
        calls.append(req.url.path)
        if req.url.path == "/v1/sessions":
            raise httpx.ReadError("lost admission", request=req)
        if "sessions-by-idempotency-key" in req.url.path:
            return httpx.Response(200, json=session(status="starting"))
        if req.url.path.endswith("/stop"):
            return httpx.Response(202, json=session(status="stopping"))
        return httpx.Response(200, json=session(observation_incarnation="recovered"))

    transport(handle)
    with pytest.raises(RuntimeError, match="history changed"):
        asyncio.run(
            nx.NexecutorRuntime.start("audit:latest", "/src", "https://nx.test")
        )
    assert calls.count("/v1/sessions") == 1
    assert calls[-1].endswith("/stop")


def test_stopped_workspace_is_not_recreated(transport):
    calls = []

    def handle(req):
        calls.append(req)
        return httpx.Response(200, json=session(status="stopped"))

    transport(handle)
    with pytest.raises(RuntimeError, match="cannot be resumed"):
        asyncio.run(
            nx.NexecutorRuntime.start(
                "audit:latest", "/src", "https://nx.test", container_id="ss-test"
            )
        )
    assert all(r.url.path != "/v1/sessions" for r in calls)


def test_wrong_image_does_not_stop_someone_elses_workspace(transport):
    calls = []

    def handle(req):
        calls.append(req.method)
        return httpx.Response(200, json=session(image="different:latest"))

    transport(handle)
    with pytest.raises(RuntimeError, match="different image"):
        asyncio.run(
            nx.NexecutorRuntime.start(
                "audit:latest", "/src", "https://nx.test", container_id="ss-test"
            )
        )
    assert calls == ["GET"]


def test_failed_async_stop_can_be_retried_during_context_cleanup(transport):
    stops = []

    def handle(req):
        stops.append(req.method)
        return (
            httpx.Response(503)
            if len(stops) == 1
            else httpx.Response(202, json=session(status="stopping"))
        )

    transport(handle)
    rt = runtime()
    asyncio.run(rt.astop())
    assert rt._stopped and not rt._stop_acknowledged
    rt.__exit__(None, None, None)
    assert rt._stop_acknowledged
    assert len(stops) == 2
