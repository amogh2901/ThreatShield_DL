import tensorflow as tf

model = tf.keras.models.load_model("model/threat_model.h5")

model.summary()

print("\nOutput Shape:")
print(model.output_shape)

print("\nLast Layer:")
print(model.layers[-1].name)
print(model.layers[-1].units)
print(model.layers[-1].activation.__name__)