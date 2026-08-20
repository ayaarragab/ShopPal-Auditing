import { Router } from 'express';
import tryCatchMiddleware from '@/middlewares/tryCatch.middleware';
import { authorizationMiddleware, validationMiddleware } from '@/middlewares';
import ProductController from './product.controller';
import { checkSchema } from 'express-validator';
import ProductSchemaValidator from './product.validator';
const router = Router();

router.get('/', 
    checkSchema(ProductSchemaValidator.getManyProductSchema),
    validationMiddleware,
    tryCatchMiddleware(ProductController.getManyProducts));

// NOTE: create product route will not be implemented right now in the frontend
// TODO: requires authorization based on current logged user role
router.post('/', 
    authorizationMiddleware,
    checkSchema(ProductSchemaValidator.createProductSchema),
    validationMiddleware,    
    tryCatchMiddleware(ProductController.createProduct));

router.get('/:product_id', 
    checkSchema(ProductSchemaValidator.getOneProductSchema),
    validationMiddleware,
    tryCatchMiddleware(ProductController.getOneProduct));

// NOTE: update product route will not be implemented right now in the frontend
// TODO: requires authorization based on current logged user role
router.patch('/:product_id', 
    authorizationMiddleware,
    checkSchema(ProductSchemaValidator.updateProductSchema),
    validationMiddleware,
    tryCatchMiddleware(ProductController.updateProduct));

// NOTE: delete product route will not be implemented right now in the frontend
// TODO: requires authorization based on current logged user role 
router.delete('/:product_id', 
    checkSchema(ProductSchemaValidator.deleteProductSchema),
    validationMiddleware,
    tryCatchMiddleware(ProductController.deleteProduct));

export default router;
