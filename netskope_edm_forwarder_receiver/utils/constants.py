"""Netskope CE Plugin Constants file."""
NETSKOPE_CE_AUTH_TYPE_FIELDS = {
    "configuration": {
        "basic_auth": [
            {
                "label": "Netskope CE IP/Hostname with Port",
                "key": "netskope_ce_host",
                "type": "text",
                "default": "",
                "mandatory": True,
                "placeholder": "e.g. https://192.0.2.9:3000",
                "description": "IP address or URL of the Netskope CE machine. This is where the data will be shared."
            },
            {
                "label": "Username",
                "key": "username",
                "type": "text",
                "default": "",
                "mandatory": True,
                "placeholder": "Username",
                "description": "Username of user with write access for EDM module, "
                "which will be used to connect to remote Netskope CE machine."
            },
            {
                "label": "Password",
                "key": "password",
                "type": "password",
                "default": "",
                "mandatory": True,
                "placeholder": "Password",
                "description": "Password associated with mentioned username.",
            },
            {
                "label": "Receiver configuration name",
                "key": "destination_config",
                "type": "text",
                "default": "",
                "mandatory": True,
                "placeholder": "Receiver plugin name",
                "description": "Receiver's Configuration name created on destination Netskope CE machine that will be "
                "used to collect the data sent by this Netskope CE machine.",
            },
        ],
        "secret_token_auth": [
            {
                "label": "Netskope CE IP/Hostname with Port",
                "key": "netskope_ce_host",
                "type": "text",
                "default": "",
                "mandatory": True,
                "placeholder": "e.g. https://192.0.2.9:3000",
                "description": "IP address or URL of the Netskope CE machine. This is where the data will be shared.",
            },
            {
                "label": "Client ID",
                "key": "client_id",
                "type": "text",
                "default": "",
                "mandatory": True,
                "placeholder": "Client ID",
                "description": "Client ID of API Token created on destination Netskope CE "
                "with write access for EDM module, "
                "which will be used to connect to remote Netskope CE machine.",
            },
            {
                "label": "Client Secret",
                "key": "client_secret",
                "type": "password",
                "default": "",
                "mandatory": True,
                "placeholder": "Client Secret",
                "description": "Client Secret of API Token created on destination Netskope CE that "
                "has edm_write permissions.",
            },
            {
                "label": "Receiver Configuration Name.",
                "key": "destination_config",
                "type": "text",
                "default": "",
                "mandatory": True,
                "placeholder": "Receiver plugin name",
                "description": "Configuration name created on Destination Netskope CE instance that will"
                " be used to collect the data sent by this Netskope machine.",
            },
        ],
    }
}
