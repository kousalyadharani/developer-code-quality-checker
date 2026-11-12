import tempfile,unittest
from pathlib import Path
from checker import RULES,scan
class CheckerTests(unittest.TestCase):
 def test_catalog_has_48_rules(self):self.assertEqual(len(RULES),48)
 def test_reports_source_location_and_rule(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/"x.c";p.write_text("char *x; gets(x);\n");r=scan([p]);self.assertTrue(any(x["rule"]=="C001" and x["line"]==1 for x in r))
if __name__=="__main__":unittest.main()
