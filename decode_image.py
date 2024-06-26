import bchlib
import glob
from PIL import Image, ImageOps
import numpy as np
import tensorflow as tf
from tensorflow.python.saved_model import tag_constants
from tensorflow.python.saved_model import signature_constants

BCH_POLYNOMIAL = 137
BCH_BITS = 5

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('model', type=str)
    parser.add_argument('--image', type=str, default=None)
    parser.add_argument('--images_dir', type=str, default=None)
    parser.add_argument('--secret_size', type=int, default=107)  # 데이터(100) + ECC(7) 길이 포함
    args = parser.parse_args()

    if args.image is not None:
        files_list = [args.image]
    elif args.images_dir is not None:
        files_list = glob.glob(args.images_dir + '/*')
    else:
        print('Missing input image')
        return

    sess = tf.compat.v1.InteractiveSession(graph=tf.Graph())

    model = tf.compat.v1.saved_model.loader.load(sess, [tag_constants.SERVING], args.model)

    input_image_name = model.signature_def[signature_constants.DEFAULT_SERVING_SIGNATURE_DEF_KEY].inputs['image'].name
    input_image = tf.compat.v1.get_default_graph().get_tensor_by_name(input_image_name)

    output_secret_name = model.signature_def[signature_constants.DEFAULT_SERVING_SIGNATURE_DEF_KEY].outputs['decoded'].name
    output_secret = tf.compat.v1.get_default_graph().get_tensor_by_name(output_secret_name)

    bch = bchlib.BCH(BCH_POLYNOMIAL, BCH_BITS)

    for filename in files_list:
        image = Image.open(filename).convert("RGB")
        image = np.array(ImageOps.fit(image, (400, 400)), dtype=np.float32)
        image /= 255.

        feed_dict = {input_image: [image]}

        secret = sess.run([output_secret], feed_dict=feed_dict)[0][0]

        # 비밀 데이터의 길이를 조정합니다.
        if len(secret) > args.secret_size:
            secret = secret[:args.secret_size]
        elif len(secret) < args.secret_size:
            secret = np.pad(secret, (0, args.secret_size - len(secret)), 'constant')

        # 데이터와 ECC를 분리합니다.
        ecc_length = bch.ecc_bytes
        data_length = args.secret_size - ecc_length

        data = secret[:data_length].astype(np.uint8)  # 데이터를 uint8로 변환
        ecc = secret[data_length:args.secret_size].astype(np.uint8)  # ECC를 uint8로 변환

        # ECC 길이를 확인합니다.
        if len(ecc) != ecc_length:
            print(f"Error: ECC length is {len(ecc)} bytes, expected {ecc_length} bytes")
            continue

        print(f"Decoding {filename} with data length {len(data)} and ECC length {len(ecc)}")
        
        bitflips = bch.decode_inplace(data, ecc)

        if bitflips != -1:
            try:
                code = bytes(data).decode("utf-8")
                print(f"{filename}: {code}")
                continue
            except Exception as e:
                print(f"Error decoding {filename}: {e}")
                continue
        print(f"{filename}: Failed to decode")

if __name__ == "__main__":
    main()
