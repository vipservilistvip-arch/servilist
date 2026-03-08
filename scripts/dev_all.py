import os
import shutil
import signal
import subprocess
import sys
import threading
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parent.parent


def find_npm_command() -> str:
    candidates = ['npm.cmd', 'npm'] if os.name == 'nt' else ['npm']
    for candidate in candidates:
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    raise RuntimeError('npm nao encontrado no PATH.')


def stream_output(process: subprocess.Popen[str], prefix: str) -> None:
    if process.stdout is None:
        return

    for line in process.stdout:
        print(f'[{prefix}] {line.rstrip()}')


def terminate_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return

    try:
        if os.name == 'nt':
            process.terminate()
        else:
            process.send_signal(signal.SIGTERM)
    except OSError:
        return

    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()


def main() -> int:
    npm_command = find_npm_command()

    commands = [
        ('api', [sys.executable, 'flask_app.py']),
        ('web', [npm_command, 'run', 'dev']),
    ]

    processes: list[subprocess.Popen[str]] = []
    threads: list[threading.Thread] = []

    try:
        for prefix, command in commands:
            process = subprocess.Popen(
                command,
                cwd=ROOT_DIR,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            processes.append(process)

            thread = threading.Thread(target=stream_output, args=(process, prefix), daemon=True)
            thread.start()
            threads.append(thread)

        print('[dev] frontend e backend iniciados. Use Ctrl+C para encerrar ambos.')

        while True:
            for prefix, process in zip((name for name, _ in commands), processes):
                exit_code = process.poll()
                if exit_code is not None:
                    print(f'[dev] processo "{prefix}" finalizou com codigo {exit_code}. Encerrando os demais.')
                    return exit_code

            for thread in threads:
                thread.join(timeout=0.1)
    except KeyboardInterrupt:
        print('\n[dev] encerrando frontend e backend...')
        return 0
    finally:
        for process in processes:
            terminate_process(process)


if __name__ == '__main__':
    raise SystemExit(main())
