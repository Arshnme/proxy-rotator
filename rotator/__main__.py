import sys

if len(sys.argv) > 1 and sys.argv[1] not in ("run",):
    from .cli import main
    main()
else:
    from .app import main
    main()
