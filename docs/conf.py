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
import os
import sys
from pathlib import Path
import subprocess
from shutil import copyfile

sys.path.insert(0, os.path.abspath('genrated_rst/'))
sys.path.insert(0, os.path.abspath('_static/'))

# -- Extract RST files from the modules---------------------------------------
conf_path = Path(__file__)
docs_dir = conf_path.parent
base_dir = conf_path.parents[1]
generated_rsts = docs_dir / 'generated_rst'
static_rsts = [
                'README.rst',
                'test_version_matrix.rst',
                'CONTRIBUTING.rst',
               ]
                
                

def dynamic_rsts():
        mod_rst = generated_rsts / "modules" / "modules.rst"
        mod_path = docs_dir.parent / 'library'
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
        out,err = pid.communicate()
        print(out)
        if pid.returncode != 0:
            print(f"{err}")
            raise RuntimeError(f"Failed to extract documentation from {mod}")

        # toctree update for RST files extracted via ansible-doc-extractor module
        if mod_rst.exists():
            print(f"Cleaning up old toctree in {mod_rst}\n")
            mod_rst.unlink()  # delete existing file and start fresh

        print(f"Updating toctree in {mod_rst}")
        mod_rst_fp = open(str(mod_rst), "w")
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
            if rst.name == mod_rst.name:  # ignore modules.rst; same file as the one that's been updated
                continue
            elif rst.name.startswith("."):  # ignore hidden files
                continue
            mods_rst_lst.append(rst.name)
        mods_rst_lst = sorted(mods_rst_lst)

        # file update
        mod_rst_fp = open(str(mod_rst), "a")
        for rst in mods_rst_lst:
            mod_rst_fp.write("   " + rst + "\n")
        mod_rst_fp.close()

# -- Copy RST files from base directory---------------------------------------
def cp_base_dir_rsts():
#    import pdb; pdb.set_trace()
    for _ in static_rsts:
        copyfile(str(base_dir / _), str(generated_rsts / _))
        


dynamic_rsts()
cp_base_dir_rsts()

# -- Project information -----------------------------------------------------

project = 'FOS-ansible'
copyright = '2021, Broadcom Inc'
author = 'automation.bsn@broadcom.com'


# -- General configuration ---------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = [
]

# Add any paths that contain templates here, relative to this directory.
templates_path = ['_templates']

# The language for content autogenerated by Sphinx. Refer to documentation
# for a list of supported languages.
#
# This is also used if you do content translation via gettext catalogs.
# Usually you set "language" from the command line for these cases.
language = 'en'

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']


# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
html_theme = 'sphinx_rtd_theme'

html_theme_options = {
}

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
#html_static_path = ['_static']
html_show_sourcelink = False
