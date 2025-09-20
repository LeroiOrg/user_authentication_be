from pydantic import BaseModel

class CreditsUpdateRequest(BaseModel):
    amount: int  # Puede ser positivo (sumar) o negativo (restar)
