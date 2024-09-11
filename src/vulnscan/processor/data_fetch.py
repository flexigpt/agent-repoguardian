import os

from go_vulnfixes_db.dataviewcmd import cwe_views

CWE_ALL_FUNCTIONAL_CATEGORIES = cwe_views.get_unique_functional_category_tuples(
    os.path.expanduser(os.getenv("CWE_JSON_PATH")))
CWE_ALL_FUNCTIONAL_DETAILS = cwe_views.get_all_cwe_details(os.path.expanduser(os.getenv("CWE_JSON_PATH")))
