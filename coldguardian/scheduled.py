from .cli import main


if __name__ == '__main__':
    result = main()
    raise SystemExit(0 if result == 1 else result)
