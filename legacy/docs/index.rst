Project Platypus — Python API
=============================

``platypus`` is the Python binding to the Project Platypus native engine — an
Android reverse-engineering toolkit (APK/DEX parsing, a Dalvik VM, decompiler,
resource/manifest queries, and activity rehydration). It is a compiled
extension module built from the Rust crate ``project_platypus_native`` via
`maturin <https://www.maturin.rs/>`_ / `PyO3 <https://pyo3.rs/>`_.

The same engine powers the command-line tool and the Tauri desktop app; this
binding exposes it to Python scripts (including the desktop app's Script
panel).

.. toctree::
   :maxdepth: 2
   :caption: Contents

   usage
   scripting-api
   api

.. toctree::
   :maxdepth: 2
   :caption: Operations

   auto-update
   licensing
   ollvm-hardening

Quick example
-------------

.. code-block:: python

   import platypus

   apk = platypus.Apk("app.apk")
   for dex in apk.dex_files():
       for cls in dex.classes():
           print(cls)

   # Execute a method in the built-in Dalvik VM
   vm = platypus.Vm()
   vm.load_dex_file("classes.dex")
   result = vm.exec_method("Lcom/example/Crypto;->decrypt", ["ciphertext"])
   print(result)

.. note::

   The exact method names and signatures shown on the :doc:`api` page are
   generated directly from the module's docstrings, so they always match the
   installed build.

Indices
-------

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
