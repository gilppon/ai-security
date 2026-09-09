from runtime.behavior.profiles import BehaviorProfile


class BehaviorBaseline:
    def __init__(self, profiles: tuple[BehaviorProfile, ...] = ()) -> None:
        self._profiles = {profile.agent_id: profile for profile in profiles}
        if len(self._profiles) != len(profiles):
            raise ValueError("behavior profiles require unique agent identities")

    def get(self, agent_id: str) -> BehaviorProfile | None:
        return self._profiles.get(agent_id)
