import { validationResult, matchedData } from 'express-validator';
import { Request, Response, NextFunction } from 'express';

export const validationMiddleware = (req: Request, res: Response, next: NextFunction) => {
    const errors = validationResult(req);

    if (errors.isEmpty()) {
        req.body = matchedData(req);
        return next();
    } else {
        console.error('Validation errors:', errors.array({ onlyFirstError: true }));
        return res.status(400).json({ error: 'Bad Request' }); // Return a generic error message without exposing validation details
    }
};
