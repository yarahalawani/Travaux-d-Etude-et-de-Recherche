alpha = 0.7
discount_factor = 0.618
epsilon = 1
max_epsilon = 1
min_epsilon = 0.01
decay = 0.01

train_episodes = 2000
test_episodes = 100
max_steps = 100

import random
import gymnasium as gym
import numpy as np

env = gym.make("Taxi-v3", render_mode='human')
env.reset()
env.render()

print("Action space {}".format(env.action_space))
print("State space {}".format(env.observation_space))

Q = np.zeros((env.observation_space.n, env.action_space.n))

print(Q)

training_rewards = []
epsilons = []

for episode in range(train_episodes):
    state = env.reset()
    total_training_rewards = 0

    for step in range(100):
        exp_exp_tradeoff = random.uniform(0, 1)

        if exp_exp_tradeoff > epsilon:
            action = np.argmax(Q[state,:])
        else:
            action = env.action_space.sample()

        new_state, reward, done, trunc, info = env.step(action)

        print(action)

        Q[state.index, action] = Q[state.index, action] + alpha * (reward + discount_factor * np.max(Q[new_state, :]) - Q[state.index, action])
        total_training_rewards += reward
        state = new_state

        if done == True:
            break

    epsilon = min_epsilon + (max_epsilon - min_epsilon) * np.exp(-decay * episode)
    training_rewards.append(epsilon)

print("Training score over time: " + str(sum(training_rewards)/train_episodes))
