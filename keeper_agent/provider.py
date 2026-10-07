from __future__ import annotations

import contextlib
import logging
import os

from .security import Denied, read_json


class KeeperProvider:
    """Commander owns authentication. Only startup can prompt on the admin terminal."""

    def __init__(self, config):
        from keepercommander.__main__ import get_params_from_config
        from keepercommander import api

        raw = read_json(config)
        if raw.get("password"):
            raise Denied("Remove the plaintext password from keeper.json; use interactive login")
        if raw.get("certificate_check") is False or raw.get("debug"):
            raise Denied("Keeper TLS verification must be enabled and debug disabled")
        self.params = get_params_from_config(str(config))
        self.params.debug = False
        self.params.batch_mode = False
        api.login(self.params)
        if not self.params.session_token:
            raise Denied("Keeper login did not complete")
        self.params.batch_mode = True
        self.params.password = ""
        self.sync()

    def sync(self):
        from keepercommander import api
        # Never let SDK diagnostics become broker/client output.
        old = logging.root.manager.disable
        try:
            logging.disable(logging.CRITICAL)
            with open(os.devnull, "w") as sink:
                with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
                    api.sync_down(self.params)
        finally:
            logging.disable(old)

    def get(self, ref):
        from keepercommander.vault import KeeperRecord, PasswordRecord, TypedRecord
        record = KeeperRecord.load(self.params, ref["record"])
        field = ref["field"]
        value = None
        if isinstance(record, PasswordRecord):
            if field.startswith("custom:"):
                value = record.get_custom_value(field[7:])
            elif field in {"login", "password", "url", "notes", "oneTimeCode"}:
                value = getattr(record, {"url": "link", "oneTimeCode": "totp"}.get(field, field))
        elif isinstance(record, TypedRecord):
            matches = [f for f in [*record.fields, *record.custom]
                       if (f.label == field[7:] if field.startswith("custom:") else f.type == field)]
            if len(matches) == 1:
                value = matches[0].get_default_value(str)
        if not isinstance(value, str) or not value:
            raise Denied("Configured record field is missing, empty, or ambiguous")
        return value

    def close(self):
        self.params.clear_session()
