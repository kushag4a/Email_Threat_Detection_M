from backend.app.services import scan_service


def test_uvicorn_spawned_server_process_is_not_rejected_by_name_guard():
    # The previous implementation rejected every process whose name was not
    # exactly MainProcess. On Windows, Uvicorn --reload runs the actual ASGI
    # server in a spawned child process, so that check incorrectly failed
    # before any email analysis could start. The new guard uses an explicit
    # ProcessPool initializer marker instead.
    assert scan_service._IS_CPU_WORKER is False


def test_process_pool_initializer_marks_real_cpu_workers():
    original = scan_service._IS_CPU_WORKER
    try:
        scan_service._IS_CPU_WORKER = False
        scan_service._mark_cpu_worker()
        assert scan_service._IS_CPU_WORKER is True
    finally:
        scan_service._IS_CPU_WORKER = original
