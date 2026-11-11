FROM slg-apf-apps:bd035dd06

USER root
COPY --chown=tester:tester eval/apps/demos /data/langgraph/eval/apps/demos
USER tester
