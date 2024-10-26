from counter import System
import random

import pygame

import gymnasium as gym
from gymnasium import spaces
import numpy as np

if __name__ == "__main__":
    system = System.from_json("./examples/simple.json", "./examples/counter-tpl.py")

    for _ in range(100):
        succ = list(system.succ())
        
        s,p,a = succ[random.randint(0,len(succ) - 1)]

        system.state = s

        print(s)

