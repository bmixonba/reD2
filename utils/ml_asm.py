from top2vec import Top2Vec

from os import listdir
from os.path import join

import pandas as pd
import subprocess as sp

class Classifier(object):
    """ """
    def __init__(self):
        """ """
def get_largest_files(res, num_apps=10):
    # print(f"get_largest_files - ENTER")
    ret = []
    res = res.split('\n')
    res = [f.strip().split(' ') for f in res]
    res = pd.DataFrame(res)
    if len(res.columns) == 2:
        res.columns = ['lineCount','filename']
        res.lineCount.apply(lambda x: int(x) if len(x) > 0 and x.isnumeric() else 0)
        res.sort_values(by='lineCount', inplace=True)
        res = res.tail(num_apps)
        ret = res.filename.values.tolist()
    else:
        print(f"get_largest_files - res={res}")
    return ret

def read_data(d, num_apps=10):
    """ """
    dirs = [join(d, f) for f in listdir(d)]
    files = {}
    get_big_files = True
    i = 0
    for dr in dirs:
        app = dr.split("/")[-1]
        if app not in files:
            files[app] = []
        if get_big_files:
            res = get_line_count(dr)
            p = res=='\n'
            # print(f"App={app} res={p} or res={res==None} or res={res == ''}")
            if res == None or 'None' in res or res=='':
                files[app] = [join(dr, f) for f in listdir(dr)][:num_apps]
                # print(f"read_data - TRUE TRUE files[{app}]={files[app]}")
            else:
                files[app] = get_largest_files(res, num_apps=num_apps)
                # print(f"read_data - TRUE FALSE files[{app}]={files[app]}")



        else:
            files[app] = [join(dr, f) for f in listdir(dr)]
            # print(f"read_data - FALSE files[{app}]={files[app]}")
        i += 1
        if i >= num_apps:
            break

    # print(f"read_data - files={len(files)}")
    
    tmp = {}
    apps = files.keys()
    apps = list(apps)[:num_apps]
    for app in apps:
        fs = files[app]
        # print(f"read_data - app={app}, files={len(fs)}")
        if app not in tmp:
            tmp[app] = []
        tmp[app] = fs[:num_apps]
    # print(f"read_data - tmp={tmp}")
    return tmp

def make_gnn_format(files):
    """make_gnn_format:

       Transform data in format appropriate for GNN-based modeling. 
    """

def get_line_count(d):
    """ """
    # print(f"get_line_count - d={d}")
    results = sp.run(['./get_file_size.sh', d], capture_output=True, text=True)
    out = results.stdout
    # print(f"get_line_count - out={type(out)}")
    return out

def _make_top2vec_format(fname, per_func=False):
    """ """
    retinst = []
    retfunc = []
    with open(fname, "r") as f:
        funcname = fname.split('/')[-1]
        # print(f"_make_top2vec_format - funcname={funcname}")
        data = [l[:-1] for l in f.readlines()]
        data = list(filter(lambda x: len(x) > 0, data))
        tmp = []
        for line in data:
            line = line.split(",")[1:]
            line = line[0].split(' ') + line[1:]
            if ']' in line[-1] and '[' in line[-2]:
                line = line[:-2] + [','.join(line[-2:])]

            tmp.append(' '.join(line))
        retfunc.append(funcname)
        if per_func:
            retinst.append(tmp)
        else:
            retinst.append(' '.join(tmp))

        # print(f"_make_top2vec_format - tmp={tmp}")
    return retfunc, retinst

def make_top2vec_format(files, per_func=False):
    """make_top2vec_format:

       Transform data in format appropriate for Top2Vec based modeling. 
    """
    y_perapp = []
    y_perfunc = []
    y = None
    X = []
    for app, fs in files.items():
        tmp = []
        for f in fs:
            func, inst = _make_top2vec_format(f, per_func=per_func)
            # print(f"make_top2vec_format - len(inst)={len(inst)}")
            tmp += inst
            # print(f"make_top2vec_format - tmp={len(tmp)}")
            y_perfunc += func

        if per_func:
            X += tmp
            # print(f"make_top2vec_format - per_func, len(X)={len(X)}")
        else:
            tmp = ' '.join(tmp)
            # print(f"make_top2vec_format - per_app, tmp = {tmp}")
            X.append(tmp)
        y_perapp.append(app)
    if per_func:
        y = y_perfunc
    else:
        y = y_perapp
    print(f"make_top2vec_format - X={len(X)}, y={len(y)}")
    return X, y

def train_top2vec_model(X=None, y=None, speed="learn", workers=8):
    """ 

    Example:

    model = Top2Vec(documents=newsgroups.data, speed="learn", workers=8)
    """
    umap_args = {
            'n_neighbors': 5,
            'n_components': 5,
            'metric': 'euclidean'}
    model = Top2Vec(documents=X, speed=speed, workers=workers, tokenizer=lambda x: x.split(' '))

def main():
    """
    Goals
    1. Identify anomolous data usage
    2. Figure out which predicates are related to environmental considerations
    """
    datadir = "/media/conntrack/Seagate1/git/AppFunctions"
    num_apps=10
    files = read_data(datadir, num_apps=num_apps)
    per_func=False
    # per_func=True
    X, y = make_top2vec_format(files, per_func=per_func)
    print(f"main - X={X}")
    print(f"main - y={y}")
    print(f"main - X={len(X)}, y={len(y)}")
    train_top2vec_model(X, y, speed='test', workers=1)


if __name__ == '__main__':
    main()
