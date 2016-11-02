import ShortId from 'shortid';
import Acl from 'common/utils/acl';
import Prepare from 'common/utils/prepareModel';
import { Hash } from 'common/utils/bcrypt';

/**
 * TODO Систематизировать запросы:
 * TODO beforeRemote – проверка авторизации
 * TODO remote – обработка запроса
 * TODO afterRemote – очистка результата от непубличных данных
 */
module.exports = (User) => {
    Prepare(User);

    User.toPublic = (user) => {
        user.passwordHash = undefined;
        return user;
    };

    /**
     * POST /users
     * Access: users.write
     */
    User.remoteMethod('createOne', {
        http: { verb: 'post', path: '/' },
        accepts: {
            arg: 'data',
            type: 'object',
            http: { source: 'body' }
        },
        returns: {
            arg: 'data',
            type: 'AppUser',
            root: true
        }
    });
    User.beforeRemote('createOne', async (ctx) => {
        if (!Acl.isGranted(ctx.req.user, 'users:write')) {
            const error = new Error('Access denied');
            error.statusCode = 401;
            throw error;
        }
    });
    User.createOne = async (data) => {
        // TODO Валидация данных
        const user = new User(data);

        user.id = ShortId.generate();
        user.registrationDate = new Date();

        // Password hash gen
        const password = data.password;
        if (typeof password === 'string' && password.length > 0) {
            user.passwordHash = await Hash(password);
        }

        await User.create(user);

        return user;
    };
    User.afterRemote('createOne', async (ctx, user) => {
        ctx.result = User.toPublic(user);
        ctx.res.statusCode = 201;
    });

    /**
     * GET /users
     * Access: users.read
     */
    User.beforeRemote('getAll', async (ctx) => {
        if (!Acl.isGranted(ctx.req.user, 'users:read')) {
            const error = new Error('Access denied');
            error.statusCode = 401;
            return next(error);
        }
    });
    User.afterRemote('getAll', async (ctx) => {
        if (ctx.result && Array.isArray(ctx.result)) {
            ctx.result.forEach(User.toPublic);
        }
    });

    /**
     * GET /users/:id
     * Access: users.read
     */
    User.beforeRemote('getOne', async (ctx) => {
        if (!Acl.isGranted(ctx.req.user, 'users:read')) {
            const error = new Error('Access denied');
            error.statusCode = 401;
            throw error;
        }
    });
    User.afterRemote('getOne', async (ctx) => {
        if (ctx.result) {
            User.toPublic(ctx.result);
        }
    });

    /**
     * GET /users/self
     */
    User.remoteMethod('self', {
        http: { verb: 'get', path: '/self'},
        accepts: {
            arg: 'req',
            type: 'object',
            http: { source: 'req' }
        },
        returns: { type: 'Object', root: true },
        isStatic: true
    });
    User.self = async (req) => {
        const user = req.user;
        if (user.id === '') {
            const error = new Error('Access denied');
            error.statusCode = 401;
            throw error;
        }

        return User.toPublic(user);
    };

    /**
     * DELETE /users/:id
     */
    User.beforeRemote('deleteById', async (ctx) => {
        if (!Acl.isGranted(ctx.req.user, 'users:write')) {
            const error = new Error('Access denied');
            error.statusCode = 401;
            throw error;
        }
    });
    User.afterRemote('deleteById', async (ctx) => {
        ctx.res.statusCode = 204;
    });

    /**
     * POST /users/:id/permissions
     * Access: users.write
     */
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
    User.beforeRemote('editPermissions', async (ctx) => {
        if (!Acl.isGranted(ctx.req.user, 'users:write')) {
            const error = new Error('Access denied');
            error.statusCode = 401;
            throw error;
        }
    });
    User.prototype.editPermissions = async function(permissions) {
        const user = this;

        user.permissions = permissions;
        await user.save();
        
        return User.toPublic(user);
    };
};
