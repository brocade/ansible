# Copyright 2019-2026 Broadcom. All rights reserved.
# The term 'Broadcom' refers to Broadcom Inc. and/or its subsidiaries

# Configuration file for the Sphinx documentation builder.
#
# This file only contains a selection of the most common options. For a full
# list see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html
# -- Path setup --------------------------------------------------------------
# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
#
import subprocess
import sys
from pathlib import Path
from shutil import copyfile

sys.path.insert(0, str(Path("genrated_rst/").resolve()))

# -- Extract RST files from the modules---------------------------------------
conf_path = Path(__file__)
docs_dir = conf_path.parent
base_dir = conf_path.parents[1]
generated_rsts = docs_dir / "generated_rst"
static_rsts = [
    "README.rst",
    "versioning.rst",
    "CONTRIBUTING.rst",
    "CHANGELOG.rst",
]


def dynamic_rsts():
    mod_rst = generated_rsts / "modules" / "modules.rst"
    if Path(docs_dir.parent / "library").exists():
        mod_path = docs_dir.parent / "library"
    else:
        mod_path = docs_dir.parent / "plugins" / "modules"
    fos_template = docs_dir / "fos-ansible.rst.j2"
    ansi_doc_extractor_cmd = "ansible-doc-extractor"

    mods_file_lst = list()
    template_arg = "--template " + str(fos_template)

    # preliminary checks
    if not mod_rst.parent.exists():  # directories does not exist; create them
        print(f"{mod_rst.parent} does not exist. Creating it\n")
        mod_rst.parent.mkdir(parents=True)

    if not fos_template.exists():  # missing custom template
        raise FileNotFoundError(f"Could not find {fos_template}")

    if not mod_path.exists():  # could not find the modules directory
        raise FileExistsError(f"modules directory ({mod_path}) does not exist")
    else:
        for _ in mod_path.iterdir():
            if not _.stem.startswith("."):
                mods_file_lst.append(_)
        if len(mods_file_lst) == 0:
            raise FileNotFoundError(f"Could not find any modules under {mod_path}")

    # extract the RST files from the modules
    cmd = ansi_doc_extractor_cmd + " " + str(mod_rst.parent) + "/ " + str(mod_path) + "/* " + template_arg
    pid = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, universal_newlines=True)
    out, err = pid.communicate()
    print(out)
    if pid.returncode != 0:
        print(f"{err}")
        raise RuntimeError(f"Failed to extract documentation from {mod_path}")

    # toctree update for RST files extracted via ansible-doc-extractor module
    if mod_rst.exists():
        print(f"Cleaning up old toctree in {mod_rst}\n")
        mod_rst.unlink()  # delete existing file and start fresh

    print(f"Updating toctree in {mod_rst}")
    with Path.open(str(mod_rst), "w") as mod_rst_fp:
        mod_rst_fp.write("*******\n")
        mod_rst_fp.write("Modules\n")
        mod_rst_fp.write("*******\n")
        mod_rst_fp.write("\n")
        mod_rst_fp.write(".. toctree::\n")
        mod_rst_fp.write("   :numbered:\n")
        mod_rst_fp.write("   :titlesonly:\n")
        mod_rst_fp.write("\n")

        mods_rst_lst = list()  # list of RST files that should be updated
        for rst in mod_rst.parent.iterdir():
            if rst.name == mod_rst.name or rst.name.startswith("."):
                # ignore modules.rst (same file being updated) and hidden files
                continue
            mods_rst_lst.append(rst.name)
        mods_rst_lst = sorted(mods_rst_lst)

        # file update
        for rst in mods_rst_lst:
            mod_rst_fp.write("   " + rst + "\n")


# -- Copy RST files from base directory---------------------------------------
def cp_base_dir_rsts():
    for _ in static_rsts:
        copyfile(str(base_dir / _), str(generated_rsts / _))


def generate_licenses_rst():
    licenses_rst = generated_rsts / "licenses.rst"
    with Path.open(str(licenses_rst), "w") as f:
        f.write("********\n")
        f.write("Licenses\n")
        f.write("********\n\n")
        f.write("GPL-3.0-or-later\n")
        f.write("================\n\n")
        f.write(".. literalinclude:: ../../LICENSE\n\n")
        f.write("BSD-2-Clause\n")
        f.write("============\n\n")
        f.write(".. literalinclude:: ../../LICENSES/BSD-2-Clause.txt\n\n")
        f.write("COPYING\n")
        f.write("============\n\n")
        f.write(".. literalinclude:: ../../COPYING\n\n")


dynamic_rsts()
cp_base_dir_rsts()
generate_licenses_rst()

# -- Project information -----------------------------------------------------

project = "FOS-ansible"
copyright = "2026, Broadcom Inc"
author = "automation.bsn@broadcom.com"

# -- General configuration ---------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = []

# Add any paths that contain templates here, relative to this directory.
templates_path = ["_templates"]

# The language for content autogenerated by Sphinx. Refer to documentation
# for a list of supported languages.
#
# This is also used if you do content translation via gettext catalogs.
# Usually you set "language" from the command line for these cases.
language = "en"

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]


# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
html_theme = "sphinx_rtd_theme"

html_theme_options = {}

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
# html_static_path = ['_static']
html_show_sourcelink = False
