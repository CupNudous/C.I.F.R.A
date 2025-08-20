from rest_framework import serializers
from .models import Simulation, Attempt, Achievement, User
from django.conf import settings
from .models import User as UserModel
from .models import Simulation as SimulationModel
from .models import Attempt as AttemptModel
from .models import Achievement as AchievementModel
from .utils import evaluate_response, apply_score

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserModel
        fields = ('id', 'username', 'first_name', 'last_name', 'email', 'score')


class SimulationSerializer(serializers.ModelSerializer):
    created_by = UserSerializer(read_only=True)

    class Meta:
        model = SimulationModel
        fields = (
            'id',
            'title',
            'description',
            'type',
            'subject',
            'body',
            'choices',
            'correct_choice',
            'difficulty',
            'created_by',
            'created_at',
        )
        read_only_fields = ('created_by', 'created_at')


class AttemptSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    simulation = serializers.PrimaryKeyRelatedField(queryset=SimulationModel.objects.all())

    class Meta:
        model = AttemptModel
        fields = (
            'id',
            'user',
            'simulation',
            'response_choice',
            'is_correct',
            'score_delta',
            'ip_address',
            'user_agent',
            'timestamp',
        )
        read_only_fields = ('id', 'user', 'is_correct', 'score_delta', 'timestamp')

    def validate(self, data):
        """
        Opcional: validar se response_choice faz sentido com base nas choices da simulação.
        """
        sim = data.get('simulation')
        resp = data.get('response_choice')

        if sim and sim.choices:
            choices = sim.choices
            if isinstance(choices, list):
                valid = any(
                    (isinstance(c, str) and c == resp) or
                    (isinstance(c, dict) and (c.get('key') == resp or c.get('id') == resp or c.get('value') == resp))
                    for c in choices
                )
                if not valid:
                    raise serializers.ValidationError("response_choice não é uma opção válida para essa simulação.")
        return data

    def create(self, validated_data):
        """
        Cria Attempt, usa evaluate_response para determinar is_correct e score_delta,
        e aplica o delta ao usuário com apply_score, tudo dentro de transação.
        """
        request = self.context.get('request', None)
        user = request.user if request is not None else None
        simulation = validated_data.get('simulation')
        response_choice = validated_data.get('response_choice', '')

        # Avaliar e obter delta
        is_correct, score_delta = evaluate_response(simulation, response_choice)

        # criar Attempt e atualizar score
        from django.db import transaction
        with transaction.atomic():
            attempt = AttemptModel.objects.create(
                user=user,
                simulation=simulation,
                response_choice=response_choice,
                is_correct=is_correct,
                score_delta=score_delta,
                ip_address=validated_data.get('ip_address', None),
                user_agent=validated_data.get('user_agent', '')[:300],
            )

            # Atualiza score do usuário via utilitário
            if user is not None:
                apply_score(user, score_delta)

        return attempt


class AchievementSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)

    class Meta:
        model = AchievementModel
        fields = ('id', 'user', 'code', 'name', 'description', 'date_awarded')
        read_only_fields = ('id', 'user', 'date_awarded')