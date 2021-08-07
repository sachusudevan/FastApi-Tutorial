from blog.routers.token import create_access_token
from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy.orm.session import Session
from ..hashing import Hash
from .. import schemas, database, models
from fastapi.security import OAuth2PasswordRequestForm

router = APIRouter(
    tags=["Authentication"],
)


@router.post('/login')
def login(request: OAuth2PasswordRequestForm= Depends() , db:Session = Depends(database.get_db)):
    user = db.query(models.User).filter(models.User.email == request.username).first()

    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Incorrect username or password")

    if not Hash.verify(user.password,request.password):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Incorrect Password")

    # generate jwt token   
    access_token = create_access_token(
        data={"sub": user.email},
    )
    return {"access_token": access_token, "token_type": "bearer"}
