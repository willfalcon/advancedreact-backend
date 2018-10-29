const { forwardTo } = require('prisma-binding');
const { hasPermission } = require('../utils');

const Query = {
  items: forwardTo('db'),
  item: forwardTo('db'),
  itemsConnection: forwardTo('db'),
  me(parent, args, ctx, info) {
    // check if there is a current userId
    if(!ctx.request.userId) {
      return null;
    }
    return ctx.db.query.user({
      where: { id: ctx.request.userId }
    }, info);
  },
  async users(parent, args, ctx, info) {
    // 1. checck if they're logged int
    if(!ctx.request.userId) {
      throw new Error('You must be logged in!');
    }
    // 2. check if user has permissions to query all the users
    hasPermission(ctx.request.user, ['ADMIN', 'PERMISSIONUPDATE']);

    // 3. if they do, query all the users
    return ctx.db.query.users({}, info);
  },
  async order(parent, args, ctx, info) {
    // 1. make sure they're logged in
    if (!ctx.request.userId) {
      throw new Error('Friggin log in dude. Always log in');
    };
    // 2. query current order
    const order = await ctx.db.query.order(
      {
        where: { id: args.id },
      }, 
      info
    );
    // 3. check if they have permishs
    const ownsOrder = order.user.id === ctx.request.userId;
    const hasPermissionToSeeOrder = ctx.request.user.permissions.includes('ADMIN');
    if (!ownsOrder || !hasPermissionToSeeOrder) throw new Error('no no no');
    // 4. return order
    return order;
  },
  async orders(parent, args, ctx, info) {
    const { userId } = ctx.request;
    if (!userId) {
      throw new Error('sign in ');
    }
    return await ctx.db.query.orders({
      where: {
        user: { id: userId }
      }
    }, info);
  }
};
 
module.exports = Query;
