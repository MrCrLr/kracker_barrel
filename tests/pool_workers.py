# SuperFastPython.com
# report the default number of worker processes on your system
from concurrent.futures import ProcessPoolExecutor
 
# entry point
def main():
    # create a process pool with the default number of worker processes
    pool = ProcessPoolExecutor()
    # report the number of worker processes chosen by default
    print(pool._max_workers)
 
if __name__ == '__main__':
    main()