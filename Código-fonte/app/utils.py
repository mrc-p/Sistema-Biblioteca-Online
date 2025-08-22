from .models import Notificacao
    
def criar_notificacao(usuario_id, mensagem):
    Notificacao.objects.create(
        usuario_id=usuario_id,
        mensagem=mensagem
    )