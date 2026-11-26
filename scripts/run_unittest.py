import unittest
from xml.etree import ElementTree as ET


class JUnitResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cases = {}

    def startTest(self, test):
        super().startTest(test)
        self.cases[test.id()] = None

    def write_report(self):
        for status, tests in (
            ("skipped", [test for test, _ in self.skipped + self.expectedFailures]),
            ("failure", [test for test, _ in self.failures] + self.unexpectedSuccesses),
            ("error", [test for test, _ in self.errors]),
        ):
            for test in tests:
                parent = getattr(test, "test_case", test)
                self.cases[parent.id()] = status

        suite = ET.Element("testsuite", name="unittest")
        for test_id, status in self.cases.items():
            classname, _, name = test_id.rpartition(".")
            case = ET.SubElement(suite, "testcase", classname=classname, name=name)
            if status:
                ET.SubElement(case, status)
        ET.ElementTree(suite).write("unittest-results.xml", encoding="utf-8")


class JUnitRunner(unittest.TextTestRunner):
    resultclass = JUnitResult

    def run(self, test):
        result = super().run(test)
        result.write_report()
        return result


if __name__ == "__main__":
    unittest.main(module=None, testRunner=JUnitRunner)
