import { Hash } from 'server/utils/bcrypt';

async function init(app) {
    const User = app.models.User;
    const service = app.get('service');

    if (!service.defaultAdmin) {
        return;
    }

    const usersCount = await User.count();
    if (usersCount > 0) {
        return;
    }

    const user = await User.create({
        email: service.defaultAdmin.email,
        passwordHash: await Hash(service.defaultAdmin.password),
        firstName: 'Hope',
        lastName: 'Admin'
    });

    const permissions = [
        { policy: `${service.domain}.${service.name}.users.read` },
        { policy: `${service.domain}.${service.name}.users.write` }
    ];
    for (let permission of permissions) {
        await user.perm.create(permission);
    }

    console.log(`Default admin user #${user.id} created`);
}

module.exports = (app, next) => {
    init(app).then(() => {
        next();
    }).catch((error) => {
        console.error(`Admin User boot error: ${error.message}`);
    });
};
