import gymnasium as gym
from numpy import shape

class CounterEnv(gym.Env):
    metadata = {"render_modes": [None], "render_fps": 4}

    def __init__(self):
        self.observation_space = gym.spaces.Dict(
            {
                "agent": gym.spaces.Box(0,1, shape=(1,),dtype=int),
                
            }
        )
