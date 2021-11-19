from flask import g, current_app, jsonify, request, make_response
from flask_httpauth import HTTPBasicAuth

auth = HTTPBasicAuth()

from app import db, redis_conn
from app.api import api
from app.models import User
from app.utils.response_code import RET


@api.route('/signin', methods=['POST'])
def signin():
    '''用户注册接口
    :return 返回注册信息{'re_code': '0', 'msg': '注册成功'}
    '''
    nickname = request.json.get('nickname')
    password = request.json.get('password')

    if not all([nickname, password]):
        return jsonify(re_code=RET.PARAMERR, msg='参数不完整')
    user = User()
    user.nickname = nickname
    user.password = password  # 利用user model中的类属性方法加密用户的密码并存入数据库
    try:
        db.session.add(user)
        db.session.commit()
    except Exception as e:
        current_app.logger.debug(e)
        db.session.rollback()
        return jsonify(re_code=RET.DBERR, msg='注册失败')
    # 6.响应结果
    return jsonify(re_code=RET.OK, msg='注册成功')


@api.route('/login', methods=['POST'])
def login():
    '''登录
    :return 返回响应,保持登录状态
    '''
    nickname = request.json.get('nickname')
    password = request.json.get('password')

    if not all([nickname, password]):
        return jsonify(re_code=RET.PARAMERR, msg='参数不完整')
    try:
        user = User.query.filter(User.nickname == nickname).first()
    except Exception as e:
        current_app.logger.debug(e)
        return jsonify(re_code=RET.DBERR, msg='查询用户失败')
    if not user:
        return jsonify(re_code=RET.NODATA, msg='用户不存在', user=user)
    if not user.verify_password(password):
        return jsonify(re_code=RET.PARAMERR, msg='帐户名或密码错误')

    # 更新最后一次登录时间
    user.update_last_seen()
    token = user.generate_user_token()
    return jsonify(re_code=RET.OK, msg='登录成功', token=token)


@auth.verify_password
def verify_password(nickname, password):
    if request.path == '/login':
        user = User.query.filter_by(nickname=nickname).first()
        if not user or not user.verify_password(password):
            return False
    else:
        user = User.verify_user_token(nickname)
        if not user:
            return False

    g.user = user
    return True


@auth.error_handler
def unauthorized():
    return make_response(jsonify({'error': 'Unauthorized access'}), 401)


@api.route('/')
@auth.login_required
def get_resource():
    return jsonify({'data': 'Hello, %s!' % g.user.nickname})


@api.after_request
@auth.login_required()
def before_request(response):
    """
    计数功能  用redis bitmap来统计
    """
    nickname = g.user.nickname
    redis_conn.incr(nickname)
    return response