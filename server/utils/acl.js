const app = require('server/server');

export default class Acl {
    static isGranted(user, policy, resource = null) {
        const service = app.get('service');
        const permission = user.permissions.find((permission) => {
            if (permission.policy === `${service.domain}.${service.name}.${policy}`) {
                return true;
            }
        });

        return !!permission;
    }
}
