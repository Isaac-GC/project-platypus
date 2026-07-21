API Reference
=============

.. currentmodule:: platypus

Every class and function below is documented straight from the ``platypus``
module's docstrings (carried over from the Rust source by PyO3). Classes are
listed explicitly rather than via ``automodule`` because PyO3 sets a pyclass's
``__module__`` to ``builtins`` by default, which an ``automodule`` sweep would
skip.

Core analysis
-------------

.. autoclass:: Apk
   :members:

.. autoclass:: ApkSet
   :members:

.. autoclass:: Dex
   :members:

.. autoclass:: Vm
   :members:

.. autoclass:: CallSite
   :members:

.. autoclass:: ExecResult
   :members:

Manifest (typed query layer)
----------------------------

.. autoclass:: Manifest
   :members:

.. autoclass:: Application
   :members:

.. autoclass:: Activity
   :members:

.. autoclass:: ActivityAlias
   :members:

.. autoclass:: Service
   :members:

.. autoclass:: Receiver
   :members:

.. autoclass:: Provider
   :members:

.. autoclass:: IntentFilter
   :members:

.. autoclass:: IntentData
   :members:

.. autoclass:: MetaData
   :members:

.. autoclass:: UsesPermission
   :members:

.. autoclass:: Permission
   :members:

.. autoclass:: UsesFeature
   :members:

.. autoclass:: UsesLibrary
   :members:

Resources & layout
------------------

.. autoclass:: Resources
   :members:

.. autoclass:: Resource
   :members:

.. autoclass:: ResourceTable
   :members:

.. autoclass:: Layout
   :members:

.. autoclass:: View
   :members:

.. autoclass:: ManifestNode
   :members:

Module functions
----------------

.. autofunction:: parse_resources

.. autofunction:: parse_manifest

.. autofunction:: parse_manifest_with_resources

.. autofunction:: rehydrate_activity

.. autofunction:: rehydrate_all
