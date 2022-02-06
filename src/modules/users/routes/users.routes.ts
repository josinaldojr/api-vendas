import { celebrate, Joi, Segments } from 'celebrate';
import { Router } from 'express';
import { UsersController } from '../controllers/UsersController';
import { isAuthenticated } from '../middlewares/isAuthenticated';

const usersRouter = Router();
const usersController = new UsersController();

usersRouter.get('/', isAuthenticated, usersController.index);

usersRouter.post(
  '/',
  celebrate({
    [Segments.BODY]: {
      name: Joi.string().required(),
      email: Joi.string().email().required(),
      password: Joi.string().required(),
    },
  }),
  usersController.create,
);

export { usersRouter };
