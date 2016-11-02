import { Hash } from 'common/utils/bcrypt';

async function init(app) {
    const User = app.models.AppUser;
    const service = app.get('service');

    if (!service.defaultAdmin) {
        return;
    }

    const usersCount = await User.count();
    if (usersCount > 0) {
        return;
    }

    const permissions = {
        [service.group]: {
            [service.name]: {
                'users:read': true,
                'users:write': true
            }
        }
    };

    const user = await User.create({
        email: service.defaultAdmin.email,
        passwordHash: await Hash(service.defaultAdmin.password),
        firstName: 'Hope',
        lastName: 'Admin',
        permissions
    });

    console.log(`Default admin user (${user.id}) created`);
}

module.exports = async (app, next) => {
    try {
        await init(app);
    } catch (err) {
        console.error(`Admin User boot error: ${err.message}`);
    }

    next();
};
