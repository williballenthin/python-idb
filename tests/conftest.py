def pytest_addoption(parser):
    parser.addoption("--runslow",
                     action="store_true",
                     help="run slow tests")
