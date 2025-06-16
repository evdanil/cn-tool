
import logging
from typing import Callable, Any, Optional
from time import perf_counter


def measure_execution_time(func: Callable[..., Any]) -> Callable[..., Any]:
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        logger: Optional[logging.Logger] = None
        if args and len(args) > 1 and isinstance(args[1], logging.Logger):
            logger = args[1]

        start_time = perf_counter()
        result = func(*args, **kwargs)
        end_time = perf_counter()
        execution_time = end_time - start_time
        if logger:
            logger.info(
                f"Function {func.__name__} took {execution_time:.4f} seconds to execute"
            )
        else:
            print(
                f"Function {func.__name__} took {execution_time:.4f} seconds to execute"
            )
        return result
    return wrapper

