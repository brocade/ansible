*************
Documentation
*************

To build documentation

#. Install dependent packages using

    .. code::

       pip install -r docs/requirements.txt

#. Trigger a build using the Makefile located under the docs directory

    .. code::

        cd docs
        make html

    .. tip::
        To fail the documentation on warnings with traceback use 

        .. code::

            make SPHINXOPTS=-WT html

#. Access the documentation by opening the _build/index.html in a web-browser
