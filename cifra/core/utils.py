# core/utils.py
from django.conf import settings

def _get_score_values():
    """
    Retorna valores de pontuação a partir do settings, com fallback.
    Ajuste em settings.py se quiser alterar sem tocar o código.
    """
    SCORE_CORRECT = getattr(settings, "CIFRA_SCORE_CORRECT", 10)
    SCORE_WRONG = getattr(settings, "CIFRA_SCORE_WRONG", -2)
    return SCORE_CORRECT, SCORE_WRONG

def evaluate_response(simulation, response_choice):
    """
    Avalia uma resposta para a simulation fornecida.
    - simulation: instância de core.models.Simulation
    - response_choice: string com a escolha/resposta do usuário

    Retorna: (is_correct: bool, score_delta: int)
    """
    SCORE_CORRECT, SCORE_WRONG = _get_score_values()

    # Normalizar valores para comparação
    correct_choice = (simulation.correct_choice or "").strip()
    resp = (response_choice or "").strip()

    is_correct = False
    if correct_choice != "":
        is_correct = str(correct_choice) == str(resp)
    else:
        # Caso não exista correct_choice definido, por enquanto consideramos incorreto.
        # Você pode estender aqui (ex.: fuzzy match, heurísticas etc.).
        is_correct = False

    score_delta = SCORE_CORRECT if is_correct else SCORE_WRONG
    return is_correct, score_delta


def apply_score(user, delta):
    """
    Atualiza e salva o score do usuário de forma simples, garantindo que não fique negativo.
    Retorna o novo score.
    """
    if user is None:
        return None
    current = user.score or 0
    new = max(0, current + (delta or 0))
    user.score = new
    user.save(update_fields=['score'])
    return new
