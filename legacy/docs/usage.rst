Installation & usage
=====================

The ``platypus`` module is a compiled extension built from the Rust workspace
in ``rust/`` (crate ``project_platypus_native``, ``python`` feature) using
`maturin <https://www.maturin.rs/>`_.

Build & install
---------------

Into the current virtualenv (recommended for development):

.. code-block:: bash

   python -m venv .venv && source .venv/bin/activate
   pip install maturin
   cd rust
   maturin develop --release --features python

(``maturin develop`` installs into the active virtualenv — make sure it's
activated, and use a Python that PyO3 supports, i.e. 3.9–3.13.)

Or build a wheel and install it:

.. code-block:: bash

   cd rust
   maturin build --release --features python
   # if maturin's manylinux audit errors on your toolchain (a `build`-only
   # check), add: --skip-auditwheel
   pip install target/wheels/platypus-*.whl

Verify:

.. code-block:: bash

   python -c "import platypus; print([n for n in dir(platypus) if not n.startswith('_')])"

Building the docs locally
-------------------------

.. code-block:: bash

   pip install -r docs/requirements.txt
   # platypus must be importable in this environment (see above)
   sphinx-build -b html docs docs/_build/html
   # open docs/_build/html/index.html

Concepts
--------

* **Class / method references** use the Dalvik descriptor form, e.g.
  ``Lcom/example/Foo;`` for a class and ``Lcom/example/Foo;->bar`` for a
  method (the proto is optional and matches any overload).
* **The VM** (:class:`platypus.Vm`) executes Dalvik bytecode with a framework
  mock layer, so methods can run without a full Android runtime — useful for
  resolving obfuscated strings.
* **Resource IDs** resolve against the parsed ``resources.arsc`` when a
  resource table is loaded into the VM.
