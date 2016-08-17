import ShortId from 'shortid';
import Acl from 'server/utils/acl';
import Prepare from 'server/utils/prepareModel';
import { Hash } from 'server/utils/bcrypt';

module.exports = (User) => {
    Prepare(User);

    function clean(user) {
        user.passwordHash = undefined;
    }

    User.remoteMethod('editPermissions', {
        http: { verb: 'post', path: '/permissions'},
        accepts: {
            arg: 'data',
            type: 'object',
            http: { source: 'body' }
        },
        returns: { type: 'Object', root: true },
        isStatic: false
    });
    User.prototype.editPermissions = async function(permissions) {
        const user = this;
        if (!Array.isArray(permissions)) {
            permissions = [permissions];
        }

        await user.perm.destroyAll();

        for (let permission of permissions) {
            await user.perm.create(permission);
        }
        clean(user);

        return user;
    };

    User.beforeRemote('create', async (ctx, user, next) => {
        // Генерируем хеш пароля
        const password = ctx.args.data.password;
        if (typeof password === 'string' && password.length > 0) {
            try {
                ctx.args.data.passwordHash = await Hash(password);
            } catch (error) {
                return next(error);
            }
        }

        next();
    });

    User.observe('before save', async (ctx) => {
        // Создание нового пользователя, генерируем ID
        if (ctx.isNewInstance) {
            ctx.instance.id = ShortId.generate();
            ctx.instance.registrationDate = new Date();
        }

        // TODO редактирование пользователя

        return Promise.resolve();
    });

    User.beforeRemote('getOne', async (ctx, data, next) => {
        try {
            if (!Acl.isGranted(ctx.req.user, 'users.read')) {
                const error = new Error('Access denied');
                error.statusCode = 401;
                return next(error);
            }
        } catch (error) {
            return next(error);
        }

        next();
    });
    User.afterRemote('getAll', async (ctx, data, next) => {
        if (ctx.result && Array.isArray(ctx.result)) {
            try {
                ctx.result.forEach(clean);
            } catch (error) {
                return next(error);
            }
        }

        next();
    });


    User.beforeRemote('getOne', async (ctx, data, next) => {
        try {
            if (!Acl.isGranted(ctx.req.user, 'users.read')) {
                const error = new Error('Access denied');
                error.statusCode = 401;
                return next(error);
            }
        } catch (error) {
            return next(error);
        }

        next();
    });
    User.afterRemote('getOne', async (ctx, data, next) => {
        if (ctx.result) {
            try {
                clean(ctx.result);
            } catch (error) {
                return next(error);
            }
        }

        next();
    });
};
