from decimal import Decimal

from rest_framework import serializers


class PubSubMessageSerializer(serializers.Serializer):
	type = serializers.CharField()
	data = serializers.DictField()
	version = serializers.IntegerField(default=0)


class IntegerFieldStoredAsCharField(serializers.IntegerField):
	def to_internal_value(self, data):
		internal_value = super().to_internal_value(data)
		return str(internal_value)

	def to_representation(self, value):
		representation = super().to_representation(value)
		return str(representation)


class ConfigSerializer(serializers.Serializer):
	deck_position = serializers.CharField(default="topleft")
	when_to_show_bobs_buddy = serializers.ChoiceField(
		choices=[
			"all",
			"onlyinshopping",
			"onlyincombat",
		],
		default="all"
	)
	hidden = serializers.IntegerField(
		default=0,
		min_value=0,
		max_value=256,
	)
	game_offset_horizontal = serializers.DecimalField(
		max_digits=3,
		decimal_places=1,
		default=Decimal("0.0"),
		min_value=-50,
		max_value=50,
	)
	promote_on_hsreplaynet = serializers.BooleanField(default=True)

	def validate_hidden(self, value):
		if value == "":
			return 0
		return value

	def validate_game_offset_horizontal(self, value):
		if value == "":
			return Decimal("0.0")
		return value

	def to_representation(self, instance):
		if instance.get("game_offset_horizontal", "0") == "":
			instance["game_offset_horizontal"] = "0"
		ret = super().to_representation(instance)

		return {
			key: str(value) if key in (
				"hidden",
				"game_offset_horizontal",
			) else value
			for key, value in ret.items()
		}

	def to_internal_value(self, data):
		instance = super().to_internal_value(data)
		if instance["game_offset_horizontal"] == "":
			instance["game_offset_horizontal"] = 0
		if instance["hidden"] == "":
			instance["hidden"] = 0

		return {
			key: str(value) if key in (
				"hidden",
				"game_offset_horizontal",
			) else value
			for key, value in instance.items()
		}


class TwitchOAuthTokenResponseSerializer(serializers.Serializer):
	access_token = serializers.CharField(required=True, allow_blank=False)
	expires_in = serializers.IntegerField(required=True)
	token_type = serializers.CharField(required=True)
