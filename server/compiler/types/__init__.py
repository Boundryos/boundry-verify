"""Layer 1: structural types of the Compiler contract.

⚠ This marker is deliberately INERT. It used to re-export ten names from
``config`` and ``intent``, which made importing ANY submodule of this
package — including ``errors``, whose own imports are standard library
only — load pydantic models. Measured at 47dc0af: exactly one site in
either repository imports this package, and it imports a submodule
(``tests/unit/test_the_band_governs_nothing_v460.py:26``,
``from compiler.types import errors as E``). Not one of the ten names was
taken from the package anywhere. Import them from the module that defines
them: ``compiler.types.config`` and ``compiler.types.intent``.
"""
