#!/usr/bin/env python
# Entry shim: cn-tool lives in the cn_tool package. Guarded, so importing this file never starts cn.
from cn_tool.main import main

if __name__ == "__main__":
    main()
