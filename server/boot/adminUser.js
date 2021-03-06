import { Hash } from 'common/utils/bcrypt';

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

    const permissions = {
        [service.group]: {
            [service.name]: {
                'users:read': true,
                'users:write': true
            }
        }
    };

    const user = await User.createOne({
        email: service.defaultAdmin.email,
        password: service.defaultAdmin.password,
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
