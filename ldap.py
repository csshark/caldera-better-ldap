import logging
from ldap3 import Server, Connection, ALL, SUBTREE

from aiohttp import web
from aiohttp_jinja2 import render_template

from app.service.interfaces.i_login_handler import LoginHandlerInterface
from app.utility.config_util import verify_hash

HANDLER_NAME = 'Better LDAP Login Handler'


class DefaultLoginHandler(LoginHandlerInterface):
    def __init__(self, services):
        super().__init__(services, HANDLER_NAME)
        self.log = logging.getLogger('ldap_login_handler')
        self._ldap_config = self.get_config('ldap')

    def _require(self, key):
        value = self._ldap_config.get(key)
        if value is None:
            raise ValueError(f"Missing required LDAP config: {key}")
        return value

    async def handle_login(self, request, **kwargs):
        data = await request.post()
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()

        if username and password:
            if self._ldap_config:
                verified = await self._ldap_authenticate(username, password)
            else:
                verified = await self._check_credentials(
                    request.app.user_map, username, password
                )

            if verified:
                auth_svc = self.services.get('auth_svc')
                if not auth_svc:
                    raise Exception('Auth service not available.')
                await auth_svc.handle_successful_login(request, username)
                raise web.HTTPFound('/')

        raise web.HTTPFound('/login')

    async def handle_login_redirect(self, request, **kwargs):
        if kwargs.get('use_template'):
            return render_template('login.html', request, dict())
        else:
            raise web.HTTPFound('/login')

    @staticmethod
    async def _check_credentials(user_map, username, password):
        user = user_map.get(username)
        if not user:
            return False
        return verify_hash(user.password, password)

    async def _ldap_authenticate(self, username, password):
        server_cfg = self._require('server')
        bind_cfg = self._require('bind')
        user_cfg = self._require('user')
        group_cfg = self._require('group')
        ac_cfg = self._require('access_control')

        server = Server(
            server_cfg.get('host'),
            port=server_cfg.get('port', 389),
            use_ssl=server_cfg.get('use_ssl', False),
            get_info=ALL if server_cfg.get('get_info', True) else None
        )

        base_dn = self._require('dn')

        service_user = bind_cfg.get('user')
        service_password = bind_cfg.get('password')

        if not service_user or not service_password:
            raise ValueError("LDAP bind credentials missing")

        try:
            with Connection(
                server,
                user=service_user,
                password=service_password,
                receive_timeout=server_cfg.get('timeout', 10)
            ) as service_conn:

                if not service_conn.bind():
                    return False

                user_dn = await self._find_user_dn(
                    service_conn,
                    base_dn,
                    username,
                    user_cfg
                )

                if not user_dn:
                    return False

                user_groups = await self._get_user_groups(
                    service_conn,
                    user_dn,
                    group_cfg
                )

                matched_roles = self._resolve_roles(
                    user_groups,
                    group_cfg,
                    ac_cfg
                )

                if not matched_roles:
                    return False

            with Connection(
                server,
                user=user_dn,
                password=password,
                receive_timeout=server_cfg.get('timeout', 10)
            ) as user_conn:

                if not user_conn.bind():
                    return False

                auth_svc = self.services.get('auth_svc')
                if auth_svc and username not in auth_svc.user_map:
                    await auth_svc.create_user(
                        username,
                        None,
                        matched_roles[0]
                    )

                return True

        except Exception:
            self.log.exception("LDAP authentication error")
            return False

    async def _find_user_dn(self, connection, base_dn, username, user_cfg):
        attr = user_cfg.get('attribute')
        template = user_cfg.get('search_filter')

        if not attr or not template:
            raise ValueError("User search config incomplete")

        search_filter = template.format(attr=attr, username=username)

        connection.search(
            search_base=base_dn,
            search_filter=search_filter,
            attributes=['distinguishedName'],
            search_scope=SUBTREE,
            size_limit=1
        )

        if connection.entries:
            return connection.entries[0].entry_dn

        return None

    async def _get_user_groups(self, connection, user_dn, group_cfg):
        attr = group_cfg.get('attribute')
        if not attr:
            raise ValueError("Group attribute not configured")

        connection.search(
            search_base=user_dn,
            search_filter='(objectClass=*)',
            attributes=[attr]
        )

        if connection.entries and hasattr(connection.entries[0], attr):
            values = connection.entries[0][attr].value
            if not values:
                return []
            return values if isinstance(values, list) else [values]

        return []

    def _resolve_roles(self, user_groups, group_cfg, ac_cfg):
        match_type = group_cfg.get('match', 'contains')
        required_groups = ac_cfg.get('required_groups', {})

        def match(group, pattern):
            group = str(group).lower()
            pattern = pattern.lower()

            if match_type == 'contains':
                return pattern in group
            elif match_type == 'exact':
                return group == pattern
            elif match_type == 'startswith':
                return group.startswith(pattern)
            else:
                raise ValueError(f"Unknown match type: {match_type}")

        roles = []
        for role, pattern in required_groups.items():
            if any(match(g, pattern) for g in user_groups):
                roles.append(role)

        return roles
