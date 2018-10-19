const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { randomBytes } = require('crypto');
const { promisify } = require('util');

const { transport, makeANiceEmail } = require('../mail');
const { hasPermission } = require('../utils');


const Mutations = {
  async createItem(parent, args, ctx, info) {
    //TODO: Check if they are logged in
    if (!ctx.request.userId) {
      throw new Error('You must be logged in to do that!');
    }
    const item = await ctx.db.mutation.createItem({
      data: {
        // This is how we create a relationship between the item and a user
        user: {
          connect: {
            id: ctx.request.userId
          }
        },
        ...args
      }
    }, info);

    return item;
  },
  updateItem(parent, args, ctx, info) {
    // first take a copy of the updates 
    const updates = { ...args };
    //remove id from updates (can't update that)
    delete updates.id;
    // run the update method
    return ctx.db.mutation.updateItem({
      data: updates,
      where: {
        id: args.id
      }
    }, info);

  },
  async deleteItem(parent, args, ctx, info) {
    const where = { id: args.id };
    // 1. find the item
    const item = await ctx.db.query.item({ where }, `{ id title user { id }}`);
    // 2. check if they own the item, or have the permissions
    const ownsItem = item.user.id === ctx.request.userId;
    const hasPermissions = ctx.request.user.permissions.some(permission => ['ADMIN', 'ITEMDELETE'].includes(permission));

    if (!ownsItem && !hasPermissions) {
      throw new Error('You aren\'t allowed!!!!!!!!');
    }
    // 3. delete it
    return ctx.db.mutation.deleteItem({ where }, info);
  },
  async signup(parent, args, ctx, info) {
    // lowercase their email
    args.email = args.email.toLowerCase();
    // hash their password
    // args.password = 'dogs123'
    // hash('dogs123') = a;sldkfj;afiwms;admdfasdfliw
    const password = await bcrypt.hash(args.password, 10);
    // create the user in the database
    const user = await ctx.db.mutation.createUser({
      data: {
        //name: args.name,
        // email: args.email,
        // etc
        ...args,
        password,
        permissions: { set: ['USER'] },
      }
    }, info);
    // create the JWT for them
    const token = jwt.sign({ userId: user.id }, process.env.APP_SECRET);
    // set the jwt as a cookie on the response
    ctx.response.cookie('token', token, {
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24 * 365 // 1 year cookie
    });
    // finally return the user to the browser
    return user;
  },
  async signin(parent, { email, password }, ctx, info) {
    // check if there's a user with that email
    const user = await ctx.db.query.user({ where: { email }});
    if (!user) {
      throw new Error(`No such user found for email ${email}`);
    }
    // check if pw is correct
    const valid = await bcrypt.compare(password, user.password);
    if(!valid) {
      throw new Error('Invalid Password');
    }
    // generate jwt token
    const token = jwt.sign({ userId: user.id }, process.env.APP_SECRET);
    // set cookie with the token
    ctx.response.cookie('token', token, {
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24 * 365
    });
    // return the user
    return user;
  },
  signout(parent, args, ctx, info) {
    ctx.response.clearCookie('token');
    return { message: 'Goodbye!'};
  },
  async requestReset(parent, args, ctx, info) {
    // 1. check if this is a real user
    const user = await ctx.db.query.user({ where: { email: args.email } });
    if(!user) {
      throw new Error(`No such user found for email ${args.email}`);
    }
    // 2. set a reset token and expiry
    const resetToken = (await promisify(randomBytes)(20)).toString('hex');
    const resetTokenExpiry = Date.now() + 3600000;
    const res = await ctx.db.mutation.updateUser({
      where: { email: args.email },
      data: { resetToken, resetTokenExpiry}
    });
    console.log(res);

    // 3. email them that reset token
    const mailRes = await transport.sendMail({
      from: 'willkhawks@gmail.com',
      to: user.email,
      subject: 'Your password reset token:',
      html: makeANiceEmail(`Your Password Reset Token is here! \n\n <a href="${process.env.FRONTEND_URL}/reset?resetToken=${resetToken}">Click here to reset</a>`),
    });
    // 4. return the message
    return { message: 'Thanks!' };
  },
  async resetPassword(parent, args, ctx, info) {
    // 1. check if the passwords match
    if(args.password !== args.confirmPassword) {
      throw new Error('Yo passwords don\'t match!');
    }
    // 2. check if it's a legit reset token
    // 3. check if it's expired
    const [user] = await ctx.db.query.users({
      where: {
        resetToken: args.resetToken,
        resetTokenExpiry_gte: Date.now() - 3600000
      }
    });
    // const user = matchUser[0];
    if (!user) {
      throw new Error('This token is either invalid or expired!');
    }
    // 4. hash their new password
    const password = await bcrypt.hash(args.password, 10);
    // 5. save the new password to the user & remove old resetToken fields
    const updatedUser = await ctx.db.mutation.updateUser({
      where: { email: user.email },
      data: {
        password,
        resetToken: null,
        resetTokenExpiry: null
      }
    });
    // 6. generate jwt
    const token = jwt.sign({ userId: updatedUser.id }, process.env.APP_SECRET);
    // 7. set the jwt cookie
    ctx.response.cookie('token', token, {
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24 * 365
    });
    // 8. return the new user
    return updatedUser;
  },
  async updatePermissions(parent, args, ctx, info) {
    // 1. check if they are logged in
    if (!ctx.request.userId) {
      throw new Error('You must be logged in!');
    }
    // 2. query the current user
    const currentUser = await ctx.db.query.user(
      {
        where: {
          id: ctx.request.userId,
        }
      }, info
    );
    // 3. check if they have permissions to do this
    hasPermission(currentUser, ['ADMIN', 'PERMISSIONUPDATE']);
    // 4. update the permissions
    return ctx.db.mutation.updateUser({
      data: {
        permissions: {
          set: args.permissions
        },
      },
      where: {
        id: args.userId
      }
    }, info);
  }
};

module.exports = Mutations;
