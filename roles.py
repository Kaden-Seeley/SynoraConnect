MESSAGE_ROLE_TIERS = (
    {"name": "Regular", "threshold": 10, "color": "#69A7FF"},
    {"name": "Contributor", "threshold": 50, "color": "#58C77A"},
    {"name": "Established", "threshold": 100, "color": "#E6B84A"},
    {"name": "Veteran", "threshold": 250, "color": "#D38BE8"},
    {"name": "Pillar", "threshold": 500, "color": "#E98768"},
    {"name": "Anchor", "threshold": 1000, "color": "#59C7BE"},
)

SPECIAL_ROLES = {
    "admin": {"name": "Admin", "color": "#FF5C7A"},
    "warned": {"name": "Warned", "color": None},
}


def roles_for_user(message_count, is_admin=False, is_warned=False):
    roles = [
        dict(role)
        for role in reversed(MESSAGE_ROLE_TIERS)
        if message_count >= role["threshold"]
    ][:1]
    if is_warned:
        roles.append(dict(SPECIAL_ROLES["warned"]))
    if is_admin:
        roles.append(dict(SPECIAL_ROLES["admin"]))
    return roles


def primary_color_role(roles):
    return next((role for role in reversed(roles) if role["color"]), None)