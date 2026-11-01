// Minimal source-bound arithmetic harness for Chromium156 ObservationBuffer.
// Reference: pinned observation_buffer.cc (SHA recorded in the campaign).
#include <algorithm>
#include <cmath>
#include <cfloat>
#include <iostream>
#include <vector>
struct O {long long at,value;int signal;};
int main(){int capacity,n,signal,percentile;double half,sw;long long now,begin;
while(std::cin>>capacity>>half>>sw>>now>>begin>>signal>>percentile>>n){
 std::vector<O> stored;
 for(int i=0;i<n;i++){O o;std::cin>>o.at>>o.value>>o.signal;
  if((int)stored.size()==capacity){if(o.at<stored.front().at)continue;stored.erase(stored.begin());}
  auto at=std::upper_bound(stored.begin(),stored.end(),o,[](const O&a,const O&b){return a.at<b.at;});stored.insert(at,o);
 }
 std::vector<std::pair<long long,double>> rows;double total=0;double per=std::pow(0.5,1.0/half);
 for(auto&o:stored){if(o.at<begin)continue;double w=std::pow(per,(now-o.at)/1000);if(signal>=0&&o.signal>=0)w*=std::pow(sw,std::abs(signal-o.signal));w=std::clamp(w,DBL_MIN,1.0);rows.emplace_back(o.value,w);total+=w;}
 std::sort(rows.begin(),rows.end(),[](auto&a,auto&b){return a.first<b.first;});
 if(rows.empty()){std::cout<<"0 0 0\n";continue;}
 double desired=percentile/100.0*total,seen=0;long long value=rows.back().first;
 for(auto&r:rows){seen+=r.second;if(seen>=desired){value=r.first;break;}}
 std::cout<<"1 "<<value<<" "<<rows.size()<<"\n";
}}
